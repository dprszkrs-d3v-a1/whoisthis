#!/usr/bin/env python3
"""
ip_lookup.py - Identify scanner IP addresses via WHOIS (RDAP) and geolocate them.

  a) WHOIS/RDAP: owner organisation, ASN, network range, registration country,
     abuse contact (useful for reporting the scanner).
  b) Geolocation: country / region / city where the IP is located.
     - Offline with a MaxMind GeoLite2-City database (--geoip-db), or
     - Online via ip-api.com (free, no key, max. 45 requests/minute).

Usage:
  python ip_lookup.py 203.0.113.5 198.51.100.7
  python ip_lookup.py -f firewall.log
  python ip_lookup.py -f scanners.txt --geoip-db GeoLite2-City.mmdb --csv result.csv
  python ip_lookup.py 203.0.113.5
  python ip_lookup.py -f scanners.txt --csv result.csv
  python ip_lookup.py 203.0.113.5 --no-shodan

Install:
  pip install ipwhois # required
  pip install geoip2 # optional, only for --geoip-db
  pip install shodan # optional if you're using the --no-shodan flag

  Things worth knowing (Shodan)
     - Query credits:
        host() is free for IPs Shodan has already indexed, but costs 1 query credit the first time an IP is requested.
        If you're out of credits, the API returns a 403 "Please upgrade your API plan" error, which your existing error
        handling will surface in the Errors line.
     - IPs not in Shodan's database (e.g., never connected to the internet, or filtered) raise shodan.APIError:
        No information available — again caught and logged per-record, so the rest of the pipeline continues.
     - CVEs:
        the vulns field may be absent on free plans (it's a paid feature); the code handles a missing key gracefully.
     - Handy options:
        client.host(ip, minify=True) trims the payload if you only need ports/org, and history=True includes historical
        banners — useful for scanner IPs that change services over time.
     - Analytical bonus for your use case:
        Shodan also reports its own ASN (shodan_asn). Comparing it against the RDAP-derived asn is a cheap sanity
        check — a mismatch can indicate BGP hijacking, proxy/hosting ranges, or recently reassigned space, which is
        exactly the kind of thing you want to know about scanner IPs.
"""
import argparse
import csv
import ipaddress
import json
import sys
import time
import os
from urllib.error import URLError
from urllib.request import urlopen

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

try:
    import geoip2.database
    import geoip2.errors
    import shodan
except ImportError:
    geoip2 = None
    shodan = None

FIELDS = [
    "ip", "org", "asn", "asn_description", "network_name", "cidr",
    "whois_country", "abuse_contacts",
    "geo_country", "geo_country_code", "geo_region",
    "geo_city", "geo_isp", "geo_source",
    "shodan_org", "shodan_isp", "shodan_asn",
    "shodan_os", "shodan_ports", "shodan_hostnames",
    "shodan_domains", "shodan_tags", "shodan_vulns",
    "shodan_services", "shodan_last_update",
    "error",
]


# ---------------------------------------------------------------- a) WHOIS
def whois_lookup(ip: str) -> dict:
    """Query RDAP (the modern, structured successor of WHOIS)."""
    res = IPWhois(ip).lookup_rdap(depth=1, retry_count=2)
    net = res.get("network") or {}
    objects = res.get("objects") or {}

    org, abuse = None, set()
    for entity in objects.values():
        roles = entity.get("roles") or []
        contact = entity.get("contact") or {}
        if "registrant" in roles and not org:
            org = contact.get("name")
        if "abuse" in roles:
            for email in contact.get("email") or []:
                if email.get("value"):
                    abuse.add(email["value"])

    return {
        "org": org or res.get("asn_description"),
        "asn": f"AS{res['asn']}" if res.get("asn") else None,
        "asn_description": res.get("asn_description"),
        "network_name": net.get("name"),
        "cidr": net.get("cidr"),
        "whois_country": net.get("country") or res.get("asn_country_code"),
        "abuse_contacts": ", ".join(sorted(abuse)),
    }


# ---------------------------------------------------------- b) Geolocation
class Geolocator:
    API_URL = ("http://ip-api.com/json/{ip}"
               "?fields=status,message,country,countryCode,regionName,city,isp")
    MIN_INTERVAL = 1.4  # seconds -> stays below 45 requests/minute

    def __init__(self, db_path=None):
        self.reader = None
        self._last_call = 0.0
        if db_path:
            if geoip2 is None:
                sys.exit("Error: 'pip install geoip2' is required for --geoip-db")
            self.reader = geoip2.database.Reader(db_path)

    '''
    locate() - return geolocation data for an IP address, either from a local
    '''
    def locate(self, ip: str) -> dict:
        return self._from_db(ip) if self.reader else self._from_api(ip)

    '''
    _from_db() - query a local GeoLite2 database for geolocation data
    '''
    def _from_db(self, ip: str) -> dict:
        try:
            r = self.reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return {"geo_source": "GeoLite2 (not found)"}
        return {
            "geo_country": r.country.name,
            "geo_country_code": r.country.iso_code,
            "geo_region": r.subdivisions.most_specific.name,
            "geo_city": r.city.name,
            "geo_source": "GeoLite2",
        }

    '''
    _from_api() - query ip-api.com for geolocation data
    '''
    def _from_api(self, ip: str) -> dict:
        wait = self.MIN_INTERVAL - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()
        with urlopen(self.API_URL.format(ip=ip), timeout=10) as resp:
            data = json.load(resp)
        if data.get("status") != "success":
            raise RuntimeError(f"ip-api: {data.get('message')}")
        return {
            "geo_country": data.get("country"),
            "geo_country_code": data.get("countryCode"),
            "geo_region": data.get("regionName"),
            "geo_city": data.get("city"),
            "geo_isp": data.get("isp"),
            "geo_source": "ip-api.com",
        }

    '''
    close() - close the GeoLite2 database reader
    '''
    def close(self):
        if self.reader:
            self.reader.close()

# ---------------------------------------------------------------- c) Shodan
class ShodanLookup:
    """Enrichment via Shodan (https://www.shodan.io/).

    Adds what Shodan's scanners observed on the host: open ports,
    product/service banners, OS guess, hostnames, domains, tags, CVEs.

    Costs: looking up an IP that has never been queried before uses
    1 query credit; IPs already indexed by Shodan are free.
    """
    MIN_INTERVAL = 1.0  # seconds between calls (conservative rate limit)

    def __init__(self, api_key=None):
        self.client = None
        self._last_call = 0.0
        if shodan is not None and api_key:
            self.client = shodan.Shodan(api_key)

    def lookup(self, ip: str) -> dict:
        """Return the shodan_* fields for one IP ({} if Shodan is disabled)."""
        if self.client is None:
            return {}

        wait = self.MIN_INTERVAL - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

        host = self.client.host(ip)

        # Compact per-service summary, e.g. "443/tcp nginx 1.18.0"
        services = []
        for b in host.get("data") or []:
            proto = (b.get("transport") or "tcp")[0]
            prod = " ".join(str(v) for v in (b.get("product"), b.get("version")) if v)
            services.append(f"{b.get('port')}/{proto} {prod}".strip())

        return {
            "shodan_org": host.get("org"),
            "shodan_isp": host.get("isp"),
            "shodan_asn": host.get("asn"),
            "shodan_os": host.get("os"),
            "shodan_ports": ", ".join(str(p) for p in sorted(host.get("ports") or [])),
            "shodan_hostnames": ", ".join(sorted(set(host.get("hostnames") or []))),
            "shodan_domains": ", ".join(sorted(set(host.get("domains") or []))),
            "shodan_tags": ", ".join(host.get("tags") or []),
            "shodan_vulns": ", ".join(sorted(host.get("vulns") or [])),
            "shodan_services": "; ".join(services),
            "shodan_last_update": host.get("last_update"),
        }

# ---------------------------------------------------------------- helpers
def parse_ip(token: str):
    """Return a public IP from a token like '1.2.3.4', '1.2.3.4:443' or '[::1]'."""
    token = token.split("=")[-1]  # e.g. iptables log "SRC=1.2.3.4"
    token = token.strip(" \t,;()[]{}<>\"'")
    if token.count(":") == 1 and "." in token:  # IPv4 with port
        token = token.split(":")[0]
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None  # skip private/reserved addresses


'''
collect_ips() - collect public IPs from command-line arguments and/or a file
'''
def collect_ips(args) -> list:
    tokens = list(args.ips)
    if args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if not line.lstrip().startswith("#"):
                    tokens.extend(line.split())
    seen, result = set(), []
    for tok in tokens:
        ip = parse_ip(tok)
        if ip and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


'''
print_record() - print a single record in a human-readable format
'''
def print_record(rec: dict):
    loc = ", ".join(x for x in (rec.get("geo_city"), rec.get("geo_region"),
                                rec.get("geo_country")) if x) or "-"
    print(f"\n{rec['ip']}")
    print(f"  Owner          : {rec.get('org') or '-'}")
    print(f"  ASN            : {rec.get('asn') or '-'} ({rec.get('asn_description') or '-'})")
    print(f"  Network        : {rec.get('network_name') or '-'} ({rec.get('cidr') or '-'})")
    print(f"  WHOIS country  : {rec.get('whois_country') or '-'}")
    print(f"  Location       : {loc}  [{rec.get('geo_source') or '-'}]")
    if rec.get("geo_isp"):
        print(f"  ISP            : {rec['geo_isp']}")
    print(f"  Abuse contact  : {rec.get('abuse_contacts') or '-'}")
    if rec.get("error"):
        print(f"  Errors         : {rec['error']}")
    # --- Shodan ---
    if any(k.startswith("shodan_") and rec[k] for k in rec):
        print(f"  Open ports     : {rec.get('shodan_ports') or '-'}")
        if rec.get("shodan_services"):
            for svc in rec["shodan_services"].split("; "):
                print(f"  Service        : {svc}")
        print(f"  Shodan org/ISP : {rec.get('shodan_org') or '-'} / {rec.get('shodan_isp') or '-'}")
        if rec.get("shodan_os"):
            print(f"  OS (guess)     : {rec['shodan_os']}")
        if rec.get("shodan_hostnames"):
            print(f"  Hostnames      : {rec['shodan_hostnames']}")
        if rec.get("shodan_tags"):
            print(f"  Tags           : {rec['shodan_tags']}")
        if rec.get("shodan_vulns"):
            print(f"  Vulnerabilities: {rec['shodan_vulns']}")
        if rec.get("shodan_last_update"):
            print(f"  Last seen      : {rec['shodan_last_update']}")

# ------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="WHOIS + geolocation for IP addresses")
    ap.add_argument("ips", nargs="*", help="IP addresses")
    ap.add_argument("-f", "--file", help="file with IPs (one per line, or any log file)")
    ap.add_argument("--geoip-db", help="path to GeoLite2-City.mmdb (offline lookup)")
    ap.add_argument("--csv", help="write results to CSV file")
    ap.add_argument("--json", help="write results to JSON file")
    ap.add_argument("--shodan-key", help="Shodan API key (else: $SHODAN_API_KEY)")
    ap.add_argument("--no-shodan", action="store_true",
                    help="skip Shodan enrichment even if a key is available")
    args = ap.parse_args()
    # --- Shodan setup ---
    key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    if key and shodan is None:
        sys.exit("Error: 'pip install shodan' is required for Shodan lookups")
    shd = ShodanLookup(key if not args.no_shodan else None)
    if shd.client is None and not args.no_shodan:
        print("Note: no Shodan API key (-s/--shodan-key or $SHODAN_API_KEY) "
              "- skipping Shodan enrichment", file=sys.stderr)
    ips = collect_ips(args)
    if not ips:
        ap.error("no public IP addresses given")

    geo = Geolocator(args.geoip_db)
    results = []
    try:
        for ip in ips:
            rec, errors = {"ip": ip}, []
            # ip lookup via WHOIS/RDAP
            try:
                rec.update(whois_lookup(ip))
            except IPDefinedError as e:
                errors.append(f"whois: {e}")
            except Exception as e:  # network errors, rate limits, ...
                errors.append(f"whois: {e}")
            # shodan lookup
            try:
                rec.update(shd.lookup(ip))
            except Exception as e:  # shodan.APIError, timeouts, ...
                errors.append(f"shodan: {e}")
            # geo lookup
            try:
                rec.update(geo.locate(ip))
            except (URLError, RuntimeError, OSError) as e:
                errors.append(f"geo: {e}")

            rec["error"] = "; ".join(errors)
            results.append(rec)
            print_record(rec)
    finally:
        geo.close()

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        print(f"\nCSV written to {args.csv}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"JSON written to {args.json}")


if __name__ == "__main__":
    main()
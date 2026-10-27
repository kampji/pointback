#!/usr/bin/env python3
"""
domainmap.py - resolve domains to IPs and report who owns them, nmap-style.

  DNS       A / AAAA (+ CNAME chain with dnspython, else the system resolver)
  IP owner  RDAP via rdap.arin.net (redirects to the right RIR) -> netname, org, range
  ASN       Team Cymru bulk whois (TCP/43) -> ASN, BGP prefix, AS name, country
  Domain    RDAP via rdap.org, once per registered domain -> registrar, dates, NS

Usage:
  domainmap.py example.com www.example.com
  domainmap.py -iL subs.txt -oN out.txt -oG out.gnmap --json out.json
  subfinder -d example.com -silent | domainmap.py -iL -

Stdlib only. Optional: pip install dnspython  (real DNS queries + CNAME chains)
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import functools
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.request

VERSION = "1.1"
HTTP_HEADERS = {"User-Agent": f"domainmap/{VERSION}", "Accept": "application/rdap+json"}

try:
    import dns.resolver  # type: ignore
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


# ------------------------------------------------------------------ input
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_-]{1,63})+$")


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def clean_domain(token):
    """Normalise one token to a bare hostname, or None if it isn't one.

    Tolerates URLs, ports, trailing dots, wildcard prefixes and the extra tokens
    in amass-style output ("www.x.com (FQDN) --> a_record --> 1.2.3.4").
    """
    d = token.strip().lower()
    d = d.split("://")[-1].split("/")[0].split(":")[0].rstrip(".")
    while d.startswith("*.") or d.startswith("."):
        d = d[2:] if d.startswith("*.") else d[1:]
    if not d or is_ip(d) or not HOSTNAME_RE.match(d):
        return None
    return d


def read_targets(positional, input_list):
    """Merge positional args and an -iL file ('-' = stdin) into a de-duped hostname list."""
    tokens = list(positional)
    if input_list:
        fh = sys.stdin if input_list == "-" else open(input_list, encoding="utf-8")
        with fh:
            for line in fh:
                tokens += line.split("#")[0].split()
    return list(dict.fromkeys(filter(None, map(clean_domain, tokens))))


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if not text or text.endswith("\n") else text + "\n")


# ------------------------------------------------------------------ DNS
@functools.lru_cache(maxsize=1)
def _resolver():
    return dns.resolver.Resolver()


def resolve(domain, timeout):
    """Return (cname_chain, [(ip, 'A'|'AAAA'), ...], error_or_None)."""
    cnames, ips, err = [], [], None
    if HAVE_DNSPYTHON:
        for rtype in ("A", "AAAA"):
            try:
                ans = _resolver().resolve(domain, rtype, lifetime=timeout)
            except dns.resolver.NXDOMAIN:
                return cnames, ips, "NXDOMAIN"
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                err = "TIMEOUT"
                continue
            except Exception as e:
                err = type(e).__name__
                continue
            for rrset in ans.response.answer:
                if rrset.rdtype == 5:  # CNAME
                    for rd in rrset:
                        target = str(rd.target).rstrip(".")
                        if target not in cnames:
                            cnames.append(target)
            ips += [(rd.to_text(), rtype) for rd in ans]
    else:
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(domain, None):
                entry = (sa[0], "AAAA" if fam == socket.AF_INET6 else "A")
                if entry not in ips:
                    ips.append(entry)
        except socket.gaierror as e:
            nx = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)}
            err = "NXDOMAIN" if e.errno in nx else (e.strerror or str(e))
    return cnames, ips, (None if ips else err or "NO A/AAAA")


def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def special_use(ip):
    """Label for addresses that won't have useful public ownership data, else None."""
    a = ipaddress.ip_address(ip)
    if a.is_global:
        return None
    for label in ("loopback", "link_local", "multicast", "private", "reserved"):
        if getattr(a, f"is_{label}"):
            return label.replace("_", "-")
    return "non-global"


# ------------------------------------------------------------------ RDAP
def get_json(url, timeout):
    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except Exception:
        return None


def _vcard(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item[0] == field and item[3]:
            return item[3]
    return None


def _find_entity(entities, role):
    for e in entities or []:
        if role in (e.get("roles") or []):
            return e
        sub = _find_entity(e.get("entities"), role)
        if sub:
            return sub
    return None


def rdap_ip(ip, timeout):
    j = get_json(f"https://rdap.arin.net/registry/ip/{ip}", timeout)
    if not j:
        return {}
    rng = None
    if j.get("cidr0_cidrs"):
        c = j["cidr0_cidrs"][0]
        rng = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
    elif j.get("startAddress"):
        rng = f"{j['startAddress']} - {j.get('endAddress', '')}"

    org = None
    for role in ("registrant", "administrative", "technical", "abuse"):
        ent = _find_entity(j.get("entities"), role)
        if ent and _vcard(ent, "fn"):
            org = _vcard(ent, "fn")
            break
    abuse_ent = _find_entity(j.get("entities"), "abuse")
    port43 = j.get("port43") or ""
    return {"netname": j.get("name"), "org": org, "range": rng,
            "country": j.get("country"),
            "abuse": _vcard(abuse_ent, "email") if abuse_ent else None,
            "rir": port43.replace("whois.", "").split(".")[0].upper() or None}


# Second-level labels commonly used under ccTLDs (co.uk, com.au, ...). Good enough
# without pulling in the Public Suffix List; install tldextract for exact results.
_CC_SLDS = {"ac", "co", "com", "edu", "gov", "govt", "net", "nhs", "org", "ltd", "plc", "mil", "ne", "or", "go"}

try:
    import tldextract  # type: ignore
    _tldx = tldextract.TLDExtract(suffix_list_urls=())  # bundled snapshot, no network
except Exception:
    _tldx = None


def registered_domain(host):
    """example.com for a.b.example.com, example.co.uk for x.example.co.uk."""
    if _tldx:
        try:
            r = _tldx(host)
            if r.domain and r.suffix:
                return f"{r.domain}.{r.suffix}"
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _CC_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@functools.lru_cache(maxsize=None)
def rdap_domain(apex, timeout):
    j = get_json(f"https://rdap.org/domain/{apex}", timeout)
    if not j:
        return {}
    events = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in j.get("events", [])}
    registrar = _find_entity(j.get("entities"), "registrar")
    registrant = _find_entity(j.get("entities"), "registrant")
    return {"registered_domain": apex,
            "registrar": _vcard(registrar, "fn") if registrar else None,
            "registrant": _vcard(registrant, "fn") if registrant else None,
            "created": events.get("registration"),
            "expires": events.get("expiration"),
            "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])]}


# ------------------------------------------------------------------ ASN (Team Cymru)
def cymru_bulk(ips, timeout):
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    buf = b""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as s:
            s.sendall(query.encode())
            while chunk := s.recv(65536):
                buf += chunk
    except Exception:
        return {}
    out = {}
    # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in buf.decode(errors="replace").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7 and parts[0].isdigit():
            out[parts[1]] = {"asn": f"AS{parts[0]}", "bgp_prefix": parts[2],
                             "cc": parts[3], "as_name": parts[6]}
    return out


# ------------------------------------------------------------------ scan
def scan(domains, args):
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        dns_f = {d: ex.submit(resolve, d, args.timeout) for d in domains}
        apex_f = {}
        if not args.no_domain:
            for apex in {registered_domain(d) for d in domains}:
                apex_f[apex] = ex.submit(rdap_domain, apex, args.timeout)

        results = []
        for d in domains:
            cnames, ips, err = dns_f[d].result()
            apex = registered_domain(d)
            results.append({"domain": d, "cnames": cnames, "error": err,
                            "addresses": [{"ip": ip, "type": t} for ip, t in ips],
                            "whois": apex_f[apex].result() if apex in apex_f else {}})

        all_ips = sorted({a["ip"] for r in results for a in r["addresses"]})
        public = [ip for ip in all_ips if not special_use(ip)]
        asn, rdap, ptrs = {}, {}, {}
        if not args.no_owner:
            asn_f = ex.submit(cymru_bulk, public, args.timeout + 5)
            rdap_f = {ip: ex.submit(rdap_ip, ip, args.timeout) for ip in public}
            asn = asn_f.result()
            rdap = {ip: f.result() for ip, f in rdap_f.items()}
        if args.ptr:
            ptrs = dict(zip(all_ips, ex.map(ptr, all_ips)))

    for r in results:
        for a in r["addresses"]:
            ip = a["ip"]
            a.update(asn.get(ip, {}))
            a.update(rdap.get(ip, {}))
            if special_use(ip):
                a["org"] = f"({special_use(ip)} address)"
            if args.ptr:
                a["ptr"] = ptrs.get(ip)
    return results


# ------------------------------------------------------------------ output
def table(rows):
    """Left-align every column except the last, which is free-width."""
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]) - 1)]
    return ["  ".join(str(c).ljust(w) for c, w in zip(row, widths)) + "  " + str(row[-1]) for row in rows]


def owner_label(a):
    owner = a.get("org") or a.get("as_name") or "-"
    if a.get("netname") and a["netname"] not in owner:
        owner += f" [{a['netname']}]"
    return owner


def fmt_normal(results, started, elapsed, verbose):
    out = [f"Starting domainmap {VERSION} at {started:%Y-%m-%d %H:%M %Z}".rstrip()]
    for r in results:
        out.append(f"\ndomainmap report for {r['domain']}")
        if r["cnames"]:
            out.append(f"CNAME chain: {' -> '.join(r['cnames'])}")
        if r["error"]:
            out.append(f"Resolution failed: {r['error']}")
            continue
        n = len(r["addresses"])
        out.append(f"Resolved: {n} address{'es' if n != 1 else ''}")

        w = r["whois"]
        if w.get("registrar"):
            line = f"Registrar: {w['registrar']}"
            if w.get("registered_domain") and w["registered_domain"] != r["domain"]:
                line += f" ({w['registered_domain']})"
            if w.get("created"):
                line += f" | created {w['created']}"
            if w.get("expires"):
                line += f" | expires {w['expires']}"
            out.append(line)
        if w.get("registrant"):
            out.append(f"Registrant: {w['registrant']}")
        if w.get("nameservers"):
            out.append(f"Nameservers: {', '.join(w['nameservers'])}")

        rows = [("ADDRESS", "TYPE", "ASN", "BGP PREFIX", "CC", "OWNER")]
        for a in r["addresses"]:
            rows.append((a["ip"], a["type"], a.get("asn", "-"),
                         a.get("bgp_prefix") or a.get("range") or "-",
                         a.get("cc") or a.get("country") or "-", owner_label(a)))
        out += table(rows)

        if verbose:
            for a in r["addresses"]:
                extras = {k: a[k] for k in ("as_name", "range", "rir", "abuse", "ptr") if a.get(k)}
                if extras:
                    out.append(f"|_{a['ip']}: " + "; ".join(f"{k}={v}" for k, v in extras.items()))

    up = sum(1 for r in results if not r["error"])
    out.append(f"\ndomainmap done: {len(results)} domain{'s' if len(results) != 1 else ''} "
               f"({up} resolved) in {elapsed:.2f} seconds")
    return "\n".join(out)


def fmt_grep(results, started):
    out = [f"# domainmap {VERSION} run at {started:%Y-%m-%d %H:%M}"]
    for r in results:
        if r["error"]:
            out.append(f"Domain: {r['domain']}\tStatus: {r['error']}")
        for a in r["addresses"]:
            out.append("\t".join([
                f"Domain: {r['domain']}", f"IP: {a['ip']}", f"Type: {a['type']}",
                f"ASN: {a.get('asn', '')}", f"Prefix: {a.get('bgp_prefix', '')}",
                f"CC: {a.get('cc') or a.get('country') or ''}",
                f"Owner: {a.get('org') or a.get('as_name') or ''}",
                f"Registrar: {r['whois'].get('registrar') or ''}"]))
    return "\n".join(out)


# ------------------------------------------------------------------ main
def main():
    p = argparse.ArgumentParser(description="Resolve domains and report IP ownership (nmap-style output).")
    p.add_argument("domains", nargs="*", help="domains (or URLs) to look up")
    p.add_argument("-iL", dest="input_list", metavar="FILE", help="read domains from FILE ('-' = stdin)")
    p.add_argument("-oN", metavar="FILE", help="write normal output to FILE")
    p.add_argument("-oG", metavar="FILE", help="write greppable output to FILE")
    p.add_argument("--json", metavar="FILE", help="write JSON to FILE (feed this to scopematch.py)")
    p.add_argument("--ptr", action="store_true", help="add reverse DNS (PTR) for each IP")
    p.add_argument("--no-owner", action="store_true", help="skip IP ownership lookups (RDAP + ASN)")
    p.add_argument("--no-domain", action="store_true", help="skip domain registration lookups")
    p.add_argument("-T", "--threads", type=int, default=10, help="worker threads (default 10)")
    p.add_argument("--timeout", type=float, default=8, help="per-lookup timeout in seconds (default 8)")
    p.add_argument("-v", "--verbose", action="store_true", help="show extra detail per IP")
    args = p.parse_args()

    domains = read_targets(args.domains, args.input_list)
    if not domains:
        p.error("no domains given (pass them as arguments or with -iL)")

    started = dt.datetime.now().astimezone()
    t0 = time.time()
    results = scan(domains, args)
    report = fmt_normal(results, started, time.time() - t0, args.verbose)

    print(report)
    if args.oN:
        write_text(args.oN, report)
    if args.oG:
        write_text(args.oG, fmt_grep(results, started))
    if args.json:
        write_text(args.json, json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

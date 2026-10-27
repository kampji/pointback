#!/usr/bin/env python3
"""
scopematch.py - match resolved (sub)domains against an in-scope IP list.

Companion to domainmap.py (keep the two files in the same folder). Input is either:
  -iL subs.txt              a raw domain list (subfinder/amass output) - resolved here
  --from-json results.json  a domainmap.py --json file - no re-resolving, keeps owner/ASN

Scope file, one or more entries per line (# comments, commas or spaces OK):
  10.1.2.3              single IP
  10.1.2.0/24           CIDR (v4 or v6)
  10.1.2.10-10.1.2.50   full range
  10.1.2.10-50          short last-octet range

Every domain lands in one bucket:
  IN SCOPE       every resolved IP is in scope
  PARTIAL        some IPs in scope, some not (CDN, load balancer, mixed hosting) - review
  OUT OF SCOPE   resolves, but nothing is in scope
  NO DNS         didn't resolve (NXDOMAIN, timeout, no A/AAAA)

It also lists scope IPs that no domain resolved to.

Usage:
  subfinder -d client.com -silent | scopematch.py -iL - -s scope.txt
  scopematch.py --from-json domainmap.json -s scope.txt --csv report.csv --hosts-out hosts.txt
"""
import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import ipaddress
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from domainmap import read_targets, resolve, table, write_text  # noqa: E402

VERSION = "1.1"
STATUSES = ["IN SCOPE", "PARTIAL", "OUT OF SCOPE", "NO DNS"]


# ------------------------------------------------------------------ scope
def parse_token(tok):
    """One scope entry -> list of networks."""
    if "-" in tok:
        start, end = tok.split("-", 1)
        start = ipaddress.ip_address(start)
        if start.version == 4 and end.isdigit():  # 10.1.2.10-50
            end = ".".join(str(start).split(".")[:3] + [end])
        end = ipaddress.ip_address(end)
        if end.version != start.version or end < start:
            raise ValueError(tok)
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(tok, strict=False)]


def parse_scope(path):
    """Return ([(network, label_as_written)], [unparseable tokens])."""
    scope, bad = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            for tok in line.split("#")[0].replace(",", " ").split():
                try:
                    scope += [(net, tok) for net in parse_token(tok)]
                except ValueError:
                    bad.append(tok)
    return scope, bad


def scope_match(ip, scope):
    """Label of the scope entry containing ip, or None."""
    a = ipaddress.ip_address(ip)
    return next((label for net, label in scope if a.version == net.version and a in net), None)


# ------------------------------------------------------------------ records
def load_records(args):
    """Return [{domain, cnames, error, addresses: [{ip, type, ...}]}]."""
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            return json.load(fh)

    domains = read_targets(args.domains, args.input_list)
    if not domains:
        sys.exit("error: no domains given (use -iL, positional args, or --from-json)")

    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        resolved = ex.map(lambda d: resolve(d, args.timeout), domains)
        return [{"domain": d, "cnames": cn, "error": err,
                 "addresses": [{"ip": ip, "type": t} for ip, t in ips]}
                for d, (cn, ips, err) in zip(domains, resolved)]


def classify(records, scope):
    for r in records:
        addrs = r.setdefault("addresses", [])
        for a in addrs:
            a["scope_match"] = scope_match(a["ip"], scope)
            a["in_scope"] = a["scope_match"] is not None
        hits = sum(a["in_scope"] for a in addrs)
        r["status"] = ("NO DNS" if not addrs else
                       "IN SCOPE" if hits == len(addrs) else
                       "PARTIAL" if hits else "OUT OF SCOPE")
    return records


def _compress(ips):
    """Sorted same-version IPs -> ['a', 'b-c', ...]."""
    out, start, prev = [], None, None
    for ip in ips:
        if start is not None and int(ip) == int(prev) + 1:
            prev = ip
            continue
        if start is not None:
            out.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = ip
    if start is not None:
        out.append(str(start) if start == prev else f"{start}-{prev}")
    return out


def unmatched_scope(records, scope, limit):
    """Per scope entry: the addresses no domain resolved to, or a note if it's too big to list."""
    hits = {ipaddress.ip_address(a["ip"]) for r in records for a in r["addresses"] if a["in_scope"]}
    groups = {}
    for net, label in scope:
        groups.setdefault(label, []).append(net)

    out = []
    for label, nets in groups.items():
        size = sum(n.num_addresses for n in nets)
        if size > limit:
            if not any(h in n for h in hits for n in nets if h.version == n.version):
                out.append((label, f"no domains resolved here ({size:,} addresses, too big to list)"))
            continue
        free = sorted((ip for n in nets for ip in (n if n.num_addresses <= 2 else n.hosts())
                       if ip not in hits), key=int)
        if free:
            out.append((label, f"{len(free)} unmatched: " + ", ".join(_compress(free))))
    return out


# ------------------------------------------------------------------ output
def owner(a):
    return a.get("org") or a.get("as_name") or ""


def fmt_report(records, scope, bad, started, elapsed, args):
    total = sum(n.num_addresses for n, _ in scope)
    entries = len({lbl for _, lbl in scope})
    out = [f"Starting scopematch {VERSION} at {started:%Y-%m-%d %H:%M %Z}".rstrip(),
           f"Scope: {entries} entr{'y' if entries == 1 else 'ies'}, {total:,} address(es)"]
    if bad:
        out.append(f"WARNING: ignored unparseable scope entries: {', '.join(bad)}")

    hidden = {s for s, flag in (("OUT OF SCOPE", args.hide_out), ("NO DNS", args.hide_nodns)) if flag}
    for status in STATUSES:
        group = sorted((r for r in records if r["status"] == status), key=lambda r: r["domain"])
        if not group or status in hidden:
            continue
        out.append(f"\n=== {status} ({len(group)}) " + "=" * max(0, 50 - len(status)))

        if status == "NO DNS":
            rows = [(r["domain"], (r.get("error") or "no A/AAAA")
                     + (f"  CNAME -> {r['cnames'][-1]}" if r.get("cnames") else "")) for r in group]
            out += table(rows)
            continue

        rows = [("DOMAIN", "ADDRESS", "SCOPE", "MATCH", "OWNER")]
        for r in group:
            for i, a in enumerate(r["addresses"]):
                rows.append((r["domain"] if i == 0 else "", a["ip"],
                             "yes" if a["in_scope"] else "NO", a["scope_match"] or "-", owner(a)))
        out += table(rows)
        out += [f"|_{r['domain']}: CNAME -> {' -> '.join(r['cnames'])}" for r in group if r.get("cnames")]

    if not args.hide_unmatched:
        unmatched = unmatched_scope(records, scope, args.expand_limit)
        if unmatched:
            out.append("\n=== SCOPE IPs WITH NO MATCHING DOMAIN " + "=" * 24)
            out += table(unmatched)

    counts = {s: sum(r["status"] == s for r in records) for s in STATUSES}
    out.append(f"\nscopematch done: {len(records)} domains -> "
               + ", ".join(f"{counts[s]} {s.lower()}" for s in STATUSES)
               + f" in {elapsed:.2f} seconds")
    return "\n".join(out)


def fmt_grep(records, started):
    empty = [{"ip": "", "in_scope": False, "scope_match": None}]
    lines = [f"# scopematch {VERSION} run at {started:%Y-%m-%d %H:%M}"]
    lines += [f"Domain: {r['domain']}\tStatus: {r['status']}\tIP: {a['ip']}"
              f"\tInScope: {'yes' if a['in_scope'] else 'no'}\tMatch: {a['scope_match'] or ''}\tOwner: {owner(a)}"
              for r in records for a in (r["addresses"] or empty)]
    return "\n".join(lines)


def write_csv(records, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "status", "ip", "type", "in_scope", "scope_match",
                    "owner", "asn", "cname_chain", "error"])
        for r in records:
            cn = " -> ".join(r.get("cnames") or [])
            if not r["addresses"]:
                w.writerow([r["domain"], r["status"], "", "", "", "", "", "", cn, r.get("error") or ""])
            for a in r["addresses"]:
                w.writerow([r["domain"], r["status"], a["ip"], a.get("type", ""), a["in_scope"],
                            a["scope_match"] or "", owner(a), a.get("asn", ""), cn, ""])


def ip_sort_key(ip):
    a = ipaddress.ip_address(ip)
    return a.version, int(a)


# ------------------------------------------------------------------ main
def main():
    p = argparse.ArgumentParser(description="Match resolved (sub)domains against an in-scope IP list.")
    p.add_argument("domains", nargs="*", help="domains to check (or use -iL / --from-json)")
    p.add_argument("-s", "--scope", required=True, metavar="FILE", help="scope file: IPs, CIDRs, ranges")
    p.add_argument("-iL", dest="input_list", metavar="FILE", help="domain list, e.g. subfinder output ('-' = stdin)")
    p.add_argument("--from-json", metavar="FILE", help="use a domainmap.py --json file instead of resolving")

    o = p.add_argument_group("output")
    o.add_argument("-oN", metavar="FILE", help="write the report to FILE")
    o.add_argument("-oG", metavar="FILE", help="write greppable output to FILE")
    o.add_argument("--csv", metavar="FILE", help="write CSV, one row per domain/IP")
    o.add_argument("--json", metavar="FILE", help="write JSON with scope results added")
    o.add_argument("--hosts-out", metavar="FILE", help="write in-scope hostnames (IN SCOPE + PARTIAL), one per line")
    o.add_argument("--ips-out", metavar="FILE", help="write unique in-scope IPs, one per line")
    o.add_argument("--strict", action="store_true", help="--hosts-out includes only fully IN SCOPE domains")

    r = p.add_argument_group("report")
    r.add_argument("--hide-out", action="store_true", help="don't list OUT OF SCOPE domains")
    r.add_argument("--hide-nodns", action="store_true", help="don't list NO DNS domains")
    r.add_argument("--hide-unmatched", action="store_true", help="don't list scope IPs with no matching domain")
    r.add_argument("--expand-limit", type=int, default=256,
                   help="list unmatched IPs for scope entries up to this size (default 256)")

    p.add_argument("-T", "--threads", type=int, default=20, help="resolver threads (default 20)")
    p.add_argument("--timeout", type=float, default=5, help="DNS timeout in seconds (default 5)")
    args = p.parse_args()

    if args.from_json and (args.domains or args.input_list):
        p.error("--from-json can't be combined with -iL or positional domains")

    scope, bad = parse_scope(args.scope)
    if not scope:
        p.error(f"no valid entries in scope file {args.scope}")

    started = dt.datetime.now().astimezone()
    t0 = time.time()
    records = classify(load_records(args), scope)
    report = fmt_report(records, scope, bad, started, time.time() - t0, args)
    print(report)

    if args.oN:
        write_text(args.oN, report)
    if args.oG:
        write_text(args.oG, fmt_grep(records, started))
    if args.csv:
        write_csv(records, args.csv)
    if args.json:
        write_text(args.json, json.dumps(records, indent=2))
    if args.hosts_out:
        keep = {"IN SCOPE"} if args.strict else {"IN SCOPE", "PARTIAL"}
        write_text(args.hosts_out, "\n".join(sorted(r["domain"] for r in records if r["status"] in keep)))
    if args.ips_out:
        ips = sorted({a["ip"] for r in records for a in r["addresses"] if a["in_scope"]}, key=ip_sort_key)
        write_text(args.ips_out, "\n".join(ips))


if __name__ == "__main__":
    main()

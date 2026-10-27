# pointback

Find the hostnames that point back into your IP scope.

On an external pentest the client usually hands you IP ranges, but the interesting stuff is often only reachable by name: virtual hosts, SNI-routed apps, a login portal that 404s on the bare IP.

Reverse DNS won't get you those names. PTR records are set by whoever owns the netblock (often the ISP or cloud provider), and an IP usually has at most one, while dozens of names can point at it. pointback goes the other way: enumerate names, resolve them forward, and keep the ones that land in scope.

```
subfinder / amass  ->  domainmap.py  ->  scopematch.py
 (find subdomains)     (DNS + owner)     (match against scope)
```

You end up with a list of hostnames that resolve into your scope, plus everything that doesn't (and why).

## Use cases

**You were given IPs only.** Run subfinder on the client's known domains and check the results against scope. Every IN SCOPE hostname is a vhost you'd otherwise miss by scanning bare IPs. Write them out with `--hosts-out` and feed the list to httpx, nuclei, or your web testing.

**You were given domains and IPs.** OUT OF SCOPE shows the client's assets sitting on infrastructure you aren't authorized to test (marketing site on a SaaS, a forgotten VPS). Don't touch them, but they're worth raising with the client as possible shadow IT.

**Coverage check.** The "no matching domain" section shows which scope IPs you still can't put a name to. Follow up with TLS certificate SANs, `--ptr`, or certificate transparency searches.

**Dangling records.** A NO DNS entry that still has a CNAME (e.g. `old.client.com -> client.herokuapp.com`) points at a resource that may no longer exist: a possible subdomain takeover. Confirm before reporting, and only claim the resource if the rules of engagement allow it.

**Reporting.** `--csv` gives one row per domain/IP pair with scope match, owner, and ASN, ready to drop into an appendix.

## Install

Python 3.8+, no required dependencies. Two optional extras make the results better:

```
pip install -r requirements.txt   # dnspython (CNAME chains), tldextract (accurate apex domains)
```

Keep `domainmap.py` and `scopematch.py` in the same folder. `scopematch` borrows the resolver from `domainmap`.

## Quick start

```bash
# 1. find subdomains
subfinder -d client.com -silent > subs.txt

# 2. resolve them and look up who owns each IP
python3 domainmap.py -iL subs.txt --json dm.json

# 3. match against the scope the client gave you
python3 scopematch.py --from-json dm.json -s scope.txt --hosts-out targets.txt
```

Short on time? Skip step 2. `scopematch` resolves names itself (you just won't get owner/ASN info):

```bash
subfinder -d client.com -silent | python3 scopematch.py -iL - -s scope.txt
```

## domainmap.py: resolve and attribute

For each domain it pulls A/AAAA records (plus the CNAME chain, if dnspython is installed), then for each IP the owning org and netblock (RDAP), the ASN and BGP prefix (Team Cymru), and the registrar and nameservers of the parent domain. Output is laid out like nmap's.

```
domainmap report for app.client.com
CNAME chain: client.azurewebsites.net
Resolved: 1 address
Registrar: MarkMonitor Inc. (client.com) | created 2004-03-11 | expires 2027-03-11
ADDRESS        TYPE  ASN      BGP PREFIX     CC  OWNER
20.119.0.40    A     AS8075   20.112.0.0/12  US  Microsoft Corporation [MSFT]
```

Useful flags:

- `-iL FILE` reads domains from a file (`-` for stdin)
- `-oN`, `-oG`, `--json` write normal, greppable, or JSON output
- `--ptr` adds reverse DNS for each IP
- `--no-owner` and `--no-domain` skip the RDAP/ASN lookups (faster, quieter)
- `-v` shows extra per-IP detail: abuse contact, RIR, PTR

## scopematch.py: sort domains by scope

Every domain lands in one of four buckets:

- **IN SCOPE**: every IP it resolves to is in scope
- **PARTIAL**: some IPs in scope, some not (often a CDN or load balancer), so review by hand
- **OUT OF SCOPE**: resolves, but nothing is in scope
- **NO DNS**: doesn't resolve (NXDOMAIN, timeout, no A/AAAA)

It also lists **scope IPs that no domain resolved to**, i.e. hosts you haven't found a name for yet.

The scope file takes one or more entries per line, with `#` comments allowed:

```
203.0.113.7               # single IP
203.0.113.0/26            # CIDR, v4 or v6
198.51.100.10-198.51.100.40
198.51.100.50-60          # short last-octet range
```

Useful flags:

- `-iL FILE` takes a raw domain list; `--from-json FILE` takes a `domainmap.py --json` file instead
- `--hosts-out FILE` writes in-scope hostnames, one per line (add `--strict` to drop PARTIAL)
- `--ips-out FILE` writes unique in-scope IPs, one per line
- `--csv`, `--json`, `-oN`, `-oG` write the report in other formats
- `--hide-out`, `--hide-nodns`, `--hide-unmatched` trim sections from the report

## Gotchas

- **Wildcard DNS.** If `*.client.com` resolves, brute-forced names will all land on the same IP and look in scope. Check for a random name like `zz9q.client.com` first, or filter with puredns or shuffledns.
- **PARTIAL is a judgment call.** A CDN edge IP being in your list doesn't mean the CDN is in scope. Test the origin, not Cloudflare.
- **Resolve from where you'll test.** Split-horizon and geo DNS can return different answers on different networks.
- **Input is forgiving.** URLs, ports, `*.` prefixes, and amass's `name (FQDN) --> a_record --> ip` lines are all reduced to bare hostnames. Single-label names (e.g. `intranet`) are skipped.
- Owner and registrar lookups hit public RDAP and whois services. Use `--no-owner --no-domain` on very large lists or if you want to stay quiet.

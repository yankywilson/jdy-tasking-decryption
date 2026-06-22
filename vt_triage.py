#!/usr/bin/env python3
"""
vt_triage.py - VirusTotal relation-export auto-tagger for JDY hunting.

PURPOSE
  Collapse VT-graph co-residency noise in one pass. Feed it the CSV exports VT
  produces for a node's relations (contacted IPs, communicating files, etc., in
  the `type,id` format) and it tags every row:

    CORROBORATED   matches a known JDY IOC (signal)
    EXCLUDED:*     CDN / cloud / RFC1918 / reserved (co-residency noise)
    REVIEW         everything else -> YOUR actual worklist

  Ordering is deliberate: the JDY-IOC check runs FIRST, so a real node is never
  auto-excluded just because it falls in a CDN-adjacent prefix.

DISCIPLINE (matches CTI_Hunting_SOP_Salt-to-Volt_Handoff.md)
  - Output is a LEAD, not a verdict. REVIEW rows need analyst validation.
  - EXCLUDED prefixes are HEURISTIC aggregates, not authoritative ASN data.
    Extend EXCLUDE_PREFIXES as you encounter new CDN/cloud ranges. When in
    doubt, an IP lands in REVIEW (fail-open to the analyst, never silently drop).
  - Co-residency is a persistent trap (SOP §4). This tool encodes that trap's
    known shape; it does not replace judgement.

USAGE
  python3 vt_triage.py <csv-or-dir-or-glob> [more ...] [options]

  # one directory of VT exports
  python3 vt_triage.py ./vt_exports/

  # explicit files
  python3 vt_triage.py contacted_ips.csv communicating_files.csv

  # only print the REVIEW worklist (suppress the noise)
  python3 vt_triage.py ./vt_exports/ --review-only

  # write tagged + review CSVs next to where you run it
  python3 vt_triage.py ./vt_exports/ -o triage_out

OPTIONS
  --review-only      print only REVIEW rows (the actionable bucket)
  -o, --out PREFIX   write PREFIX_tagged.csv and PREFIX_review.csv
  --no-write         do not write output CSVs (print only)

NO EXTERNAL DEPS - Python 3 stdlib only.
"""

import argparse
import csv
import glob
import ipaddress
import os
import sys
from collections import Counter, defaultdict

# ============================================================================
# EDIT THIS BLOCK - JDY IOC SET (signal). Source: Lumen JDY_6_2026_IOCs.txt.
# Add new confirmed nodes/hashes here as the hunt progresses.
# ============================================================================
JDY_IPS = {
    "216.173.65.250",   # C2 (Evoxt)
    "194.14.217.88",    # C2 (M247 Romania)
    "23.27.120.240",    # C2 (Evoxt)   <-- note: 23.x but NOT Akamai; IOC check protects it
    "109.104.154.116",  # C2 (BrainStorm NL)
    "140.82.23.123",    # historical C2 (Vultr, 2023)
    "149.248.3.38",     # payload/tasking server (Vultr LA)
}

JDY_FILES = {
    # payloads (MIPS/MIPS64/MIPSEL)
    "40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed",
    "28a23ab78739de674f94d9acadfe0709862c2b2d947e9051b200a24d3f9f45c4",
    "d1414803a83b1ba260e3e1be742379eccbb806f987ec1e7c0bc5399e4971a58f",
    # droppers (bash)
    "03c4667f016f1e8441177639d87f77a59f32d2c7e0041616376967338667bd3b",
    "1e0da906811b570c4134ade310c3a94631d4b308d27b616497266b49aae2ad0a",
    "d62055910cd579ff1fb57bd1926c5b2e80e1677f0316737b2f733f86b01615dc",
    # Platypus / Termite client
    "96ecc107aa645e36b5f939ebfcf9e61fc9ebc27616680fbd0fdeb41c7950d79a",
}

# jdyfj self-signed cert (SHA-256). VT 'historical SSL certificates' may carry this.
JDY_CERTS = {
    "2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf",
}

# C2 is Tor-hidden; no clearnet JDY domains published. Add if any surface.
JDY_DOMAINS = set()

# ============================================================================
# EDIT THIS BLOCK - KNOWN CO-TENANT DOMAINS (noise).
# Registrable domains confirmed as shared-hosting / co-residency artifacts on a
# JDY-adjacent VPS (NOT JDY infra - JDY C2 is Tor-hidden + raw-IP, zero clearnet
# domain IOCs by design). Any domain whose registrable base is in this set, or
# any subdomain of it, auto-tags EXCLUDED instead of landing in REVIEW.
# Add the registrable base only (e.g. "faucetpot.xyz"); subdomains match too.
# ============================================================================
EXCLUDE_DOMAINS = {
    "faucetpot.xyz",      # shared cPanel co-tenant on 149.248.3.38 (Vultr LA)
    "oakenfjrod.ru",      # infostealer co-tenant on 23.27.120.240 (Evoxt)
    "gerenciadores.com",  # Brazilian shared-hosting reseller on 45.32.174.13 (rotated)
}

# Subdomain labels that signal generic shared-hosting control panels (cPanel/
# webmail/ftp/mail/etc.). Presence is corroborating evidence of a co-tenant,
# used only as a SOFT signal in the reason string - never the sole basis for
# exclusion (the EXCLUDE_DOMAINS base match is what triggers the tag).
_SHARED_HOSTING_LABELS = {"cpanel", "webmail", "webdisk", "whm", "ftp", "mail",
                          "autodiscover", "autoconfig", "pop", "smtp", "ns1", "ns2"}

# ============================================================================
# EDIT THIS BLOCK - CO-RESIDENCY EXCLUSION PREFIXES (noise).
# HEURISTIC CDN/cloud aggregates. Intentionally avoid over-broad /8s that would
# swallow non-CDN tenants (e.g. 23.0.0.0/8 would wrongly cover Evoxt 23.27.x).
# Extend freely. Anything not matched here falls through to REVIEW.
# ============================================================================
EXCLUDE_PREFIXES = {
    "Akamai": [
        "2.16.0.0/13", "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
        "23.215.0.0/16", "23.216.0.0/13", "95.100.0.0/15", "104.64.0.0/10",
        "184.24.0.0/13", "184.50.0.0/15", "88.221.0.0/16", "96.6.0.0/15",
    ],
    "Cloudflare": [
        "104.16.0.0/13", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
        "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "131.0.72.0/22", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18",
        "2606:4700::/32",
    ],
    "Fastly": [
        "199.232.0.0/16", "151.101.0.0/16", "23.235.32.0/20", "43.249.72.0/22",
        "103.244.50.0/24", "146.75.0.0/16", "167.82.0.0/17",
    ],
    "Microsoft/Azure": [
        "20.32.0.0/11", "20.64.0.0/10", "40.64.0.0/10", "52.184.0.0/13",
        "13.64.0.0/11", "104.40.0.0/13", "168.61.0.0/16", "137.116.0.0/15",
        "150.171.0.0/16", "51.10.0.0/15", "4.144.0.0/12", "13.104.0.0/14",
    ],
    "Google": [
        "8.8.4.0/24", "8.8.8.0/24", "34.96.0.0/12", "35.190.0.0/17",
        "74.125.0.0/16", "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
        "2607:f8b0::/32",
    ],
    "Edgecast/Edgio": [
        "192.229.0.0/16", "72.21.80.0/20", "93.184.208.0/20", "198.7.16.0/20",
    ],
    "Amazon/AWS-CloudFront": [
        "13.32.0.0/15", "13.224.0.0/14", "99.84.0.0/16", "143.204.0.0/16",
        "205.251.192.0/19", "54.230.0.0/16", "54.239.128.0/18",
    ],
}

# ---------------------------------------------------------------------------
# Precompute exclusion networks: list of (owner, ip_network)
# ---------------------------------------------------------------------------
_EXCLUDE_NETS = []
for _owner, _cidrs in EXCLUDE_PREFIXES.items():
    for _c in _cidrs:
        try:
            _EXCLUDE_NETS.append((_owner, ipaddress.ip_network(_c, strict=False)))
        except ValueError:
            sys.stderr.write(f"[warn] bad CIDR in EXCLUDE_PREFIXES: {_c}\n")


def classify_ip(value):
    """Return (tag, reason) for an IP string."""
    v = value.strip()
    # 1) JDY IOC always wins
    if v in JDY_IPS:
        return ("CORROBORATED", "JDY cluster IP (Lumen IOC)")
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return ("REVIEW", "unparseable IP literal")
    # 2) Reliable stdlib categories (deterministic)
    if ip.is_private:
        return ("EXCLUDED:private", "RFC1918/ULA private (sandbox LAN)")
    if ip.is_loopback:
        return ("EXCLUDED:reserved", "loopback")
    if ip.is_link_local:
        return ("EXCLUDED:reserved", "link-local")
    if ip.is_multicast:
        return ("EXCLUDED:reserved", "multicast")
    if ip.version == 4 and ipaddress.ip_network("100.64.0.0/10").supernet_of(
        ipaddress.ip_network(f"{v}/32")
    ):
        return ("EXCLUDED:reserved", "CGNAT 100.64/10")
    if ip.is_reserved or (not ip.is_global and not ip.is_private):
        return ("EXCLUDED:reserved", "reserved / non-global (likely sandbox artifact)")
    # 3) CDN / cloud heuristic prefixes
    for owner, net in _EXCLUDE_NETS:
        if ip.version == net.version and ip in net:
            return (f"EXCLUDED:cdn", f"{owner} {net} (co-residency)")
    # 4) Unknown -> analyst worklist
    return ("REVIEW", "no IOC/CDN/reserved match - VALIDATE")


def classify_file(value):
    v = value.strip().lower()
    if v in {h.lower() for h in JDY_FILES}:
        return ("CORROBORATED", "JDY payload/dropper/Platypus hash (Lumen IOC)")
    # Cannot auto-exclude a hash without file-type context; default to REVIEW.
    # (Reminder: VT 'communicating files'/'PE resource parents' for a MIPS ELF
    #  are almost always Windows-PE co-residency fan-out - but confirm per hash.)
    return ("REVIEW", "non-IOC file - check filetype/arch; PE != MIPS ELF")


def classify_cert(value):
    v = value.strip().lower()
    if v in {c.lower() for c in JDY_CERTS}:
        return ("CORROBORATED", "jdyfj cert (SHA-256, Lumen IOC)")
    return ("REVIEW", "non-IOC certificate - inspect CN/SPKI for jdyfj reuse")


def _registrable_suffix_match(host, bases):
    """True if host == base or host endswith '.'+base for any base in bases.
    Suffix match on a label boundary - so 'faucetpot.xyz' matches
    'mail.faucetpot.xyz' but NOT 'notfaucetpot.xyz'."""
    h = host.strip().lower().rstrip(".")
    for base in bases:
        b = base.lower().rstrip(".")
        if h == b or h.endswith("." + b):
            return base
    return None


def classify_generic(rtype, value):
    v = value.strip()
    if rtype in ("domain",) and v in JDY_DOMAINS:
        return ("CORROBORATED", "JDY domain")
    if rtype in ("domain", "hostname"):
        base = _registrable_suffix_match(v, EXCLUDE_DOMAINS)
        if base:
            # soft enrichment: note if it's an obvious shared-hosting panel label
            label = v.strip().lower().split(".")[0]
            panel = " (shared-hosting panel label)" if label in _SHARED_HOSTING_LABELS else ""
            return ("EXCLUDED:co-tenant",
                    f"co-tenant of {base} - shared hosting, not JDY{panel}")
    return ("REVIEW", f"{rtype}: no IOC match - VALIDATE")


def classify(rtype, value):
    rtype = (rtype or "").strip().lower()
    if rtype == "ip_address":
        return classify_ip(value)
    if rtype == "file":
        return classify_file(value)
    if rtype in ("ssl_cert", "certificate", "x509"):
        return classify_cert(value)
    return classify_generic(rtype, value)


def load_rows(paths):
    """Expand files/dirs/globs -> list of CSV paths, then read (type,id) rows.
    Returns dict: (type, id) -> set(source_files). Dedups across files."""
    csv_files = []
    for p in paths:
        if os.path.isdir(p):
            csv_files += sorted(glob.glob(os.path.join(p, "*.csv")))
        elif any(ch in p for ch in "*?[]"):
            csv_files += sorted(glob.glob(p))
        elif os.path.isfile(p):
            csv_files.append(p)
        else:
            sys.stderr.write(f"[warn] path not found: {p}\n")
    if not csv_files:
        sys.stderr.write("[error] no CSV files resolved from inputs\n")
        sys.exit(2)

    rows = defaultdict(set)
    for f in csv_files:
        try:
            with open(f, newline="") as fh:
                rdr = csv.reader(fh)
                for r in rdr:
                    if not r or len(r) < 2:
                        continue
                    rtype = r[0].strip()
                    rid = r[1].strip()
                    if not rtype or rtype.lower() == "type" or not rid:
                        continue
                    rows[(rtype, rid)].add(os.path.basename(f))
        except Exception as e:  # noqa
            sys.stderr.write(f"[warn] failed reading {f}: {e}\n")
    return rows, csv_files


def main():
    ap = argparse.ArgumentParser(
        description="Auto-tag VT relation exports: JDY signal vs co-residency noise."
    )
    ap.add_argument("inputs", nargs="+", help="CSV files, directories, or globs")
    ap.add_argument("--review-only", action="store_true",
                    help="print only REVIEW rows (the worklist)")
    ap.add_argument("-o", "--out", default=None,
                    help="write <PREFIX>_tagged.csv and <PREFIX>_review.csv")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write any output CSVs")
    args = ap.parse_args()

    rows, csv_files = load_rows(args.inputs)

    tagged = []  # (tag, reason, rtype, rid, sources)
    for (rtype, rid), srcs in rows.items():
        tag, reason = classify(rtype, rid)
        tagged.append((tag, reason, rtype, rid, ",".join(sorted(srcs))))

    # sort: CORROBORATED first, then REVIEW, then EXCLUDED groups
    def sort_key(t):
        order = {"CORROBORATED": 0, "REVIEW": 1}
        return (order.get(t[0], 2), t[0], t[2], t[3])
    tagged.sort(key=sort_key)

    counts = Counter(t[0] for t in tagged)
    corrob = [t for t in tagged if t[0] == "CORROBORATED"]
    review = [t for t in tagged if t[0] == "REVIEW"]

    # ---- report ----
    print("=" * 64)
    print("VT RELATION TRIAGE - JDY")
    print("=" * 64)
    print(f"inputs: {len(csv_files)} CSV file(s); {len(tagged)} unique indicators")
    print("\nTAG SUMMARY")
    for tag in sorted(counts, key=lambda k: (k != "CORROBORATED", k != "REVIEW", k)):
        print(f"  {counts[tag]:4d}  {tag}")

    if corrob:
        print("\n--- CORROBORATED (signal) ---")
        for tag, reason, rtype, rid, srcs in corrob:
            print(f"  [{rtype}] {rid}  <-  {reason}")
    else:
        print("\n--- CORROBORATED (signal): NONE ---")

    print(f"\n--- REVIEW worklist ({len(review)}) - VALIDATE THESE ---")
    if review:
        for tag, reason, rtype, rid, srcs in review:
            print(f"  [{rtype}] {rid}  ::  {reason}")
    else:
        print("  (empty - all rows auto-classified as signal or noise)")

    if not args.review_only:
        excl = [t for t in tagged if t[0].startswith("EXCLUDED")]
        ebreak = Counter(t[1].split(" (")[0].split("/")[0] if t[0] == "EXCLUDED:cdn"
                         else t[0] for t in excl)
        print(f"\n--- EXCLUDED (co-residency noise): {len(excl)} suppressed ---")
        owners = Counter()
        for t in excl:
            if t[0] == "EXCLUDED:cdn":
                owners[t[1].split(" ")[0]] += 1
            else:
                owners[t[0]] += 1
        for k, v in owners.most_common():
            print(f"  {v:4d}  {k}")

    # ---- write outputs ----
    if not args.no_write:
        prefix = args.out or "vt_triage_out"
        tagged_path = f"{prefix}_tagged.csv"
        review_path = f"{prefix}_review.csv"
        with open(tagged_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["tag", "type", "id", "reason", "source_files"])
            for tag, reason, rtype, rid, srcs in tagged:
                w.writerow([tag, rtype, rid, reason, srcs])
        with open(review_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "id", "reason", "source_files"])
            for tag, reason, rtype, rid, srcs in review:
                w.writerow([rtype, rid, reason, srcs])
        print(f"\nwrote: {tagged_path}  ({len(tagged)} rows)")
        print(f"wrote: {review_path}  ({len(review)} rows)")

    # exit non-zero if anything needs review (handy in pipelines)
    sys.exit(1 if review else 0)


if __name__ == "__main__":
    main()

# JDY Botnet — Intelligence Report

**Subject:** JDY reconnaissance botnet (China-nexus, KV/JDY lineage, MITRE **G1017**)
**Reporting basis:** Lumen Black Lotus Labs (June 2026) + independent RE and infrastructure
analysis in this repository
**Classification:** TLP:CLEAR · ICD-203 estimative language · **NOVEL / CORROBORATED /
PUBLISHED / EXCLUDED** tagging

This report is tiered so each level of the chain takes what it needs at its own altitude:
**Strategic** (leadership / CISO), **Operational** (threat-intel / IR management),
**Tactical** (SOC / hunt / detection engineering). Read your tier; the others are there for
context.

---

# 1. Strategic — for leadership and the CISO

## Bottom line up front

JDY is a **persistent, China-nexus reconnaissance capability** that maps exposed
internet-facing systems at scale and feeds that targeting to follow-on operators — often
**within hours of a vulnerability becoming public**. It does not exploit, steal, or
disrupt; it **finds**. It is assessed as a shared, multi-actor capability supporting
China-nexus operations including Volt Typhoon (G1017). It survived the 2024 KV-botnet
takedown and **roughly doubled** (≈650 → 1,500+ devices), which means **disrupting nodes
does not remove the capability** — it adapts and rebuilds.

## Why this matters to the business

- **The patch window is effectively gone for perimeter devices.** JDY has been observed
  scanning for a newly disclosed Fortinet flaw (CVE-2026-35616) within hours of disclosure.
  Standard 30–90 day patch cycles for internet-facing edge gear are no longer defensible
  against this class of adversary.
- **IP-based defenses are degraded.** Scanning comes from thousands of compromised,
  legitimate-looking residential/SOHO addresses across the US, Europe, and Asia.
  Geofencing, static blocklists, and IP reputation, **used alone**, do not stop it.
- **The visibility gap is at the edge.** Routers, firewalls, VPNs, and cameras are often
  outside the same monitoring rigor as endpoints and cloud. That gap is exactly where this
  adversary operates.
- **Sector relevance.** Observed targeting skews heavily toward **US military and
  associated networks**. Organizations in or adjacent to that supply chain should treat
  this as elevated relevance.

## What we assess (with confidence)

| Assessment | Confidence |
|---|---|
| JDY is an active, China-nexus reconnaissance capability of the KV/JDY lineage | **High** |
| Reconnaissance output is rapidly operationalized for follow-on exploitation | **High** |
| The capability persists and rebuilds despite node-level disruption | **High** |
| Attribution to any single actor (incl. Volt Typhoon specifically) | **Moderate** — it is shared infrastructure; attribution caps below single-actor certainty |

## Decisions this report supports

- Authorize **accelerated/emergency patching** for internet-facing edge devices, decoupled
  from the standard SLA.
- Fund **edge-device visibility** (telemetry from routers/firewalls/VPNs) to close the gap
  this adversary exploits.
- Pre-approve **perimeter response playbooks** (see Operational §2) so SOC can act without
  waiting for change-management on a disclosure day.
- Treat **end-of-life edge hardware** as a standing risk item — it is prime recruitment
  material for this botnet.

---

# 2. Operational — for threat-intel and IR management

## Capability profile

JDY is a **centrally controlled, high-performance scanning engine**, not an exploitation
framework. The architecture is layered and built for operator concealment:

- **Bots** (≈1,500 compromised SOHO/IoT devices: Cisco, Araknis, Mimosa, Ubiquiti,
  DrayTek, Hikvision, Linksys) perform multiprotocol probing — **TCP, SSL, UDP, ICMP** —
  and capture service banners, TLS certificates, and protocol fingerprints.
- **Dispatch service (C2)** issues encrypted scanning tasks and fingerprint-rule updates;
  it is **Tor-hidden by design**.
- **Payload/tasking host** delivers per-architecture implants and is, in some cases,
  managed with the open-source **Platypus** reverse-shell framework.
- **Privilege-adaptive scanning:** with a raw socket (root), it runs fast custom **SYN**
  scanning; otherwise it falls back to standard TCP/TLS, UDP, ICMP.

## How the operation runs (kill-chain framing)

1. **Recruit** — weaponize a newly disclosed edge-device CVE → bash dropper checks arch,
   downloads the matching MIPS/MIPSEL payload, executes, **self-deletes from disk**.
2. **Register** — implant fingerprints the host, checks in to the dispatch service
   (`probe_status`).
3. **Task** — pulls **encrypted** tasking (`probe_task`): base64 → AES → JSON, containing
   `scan_type`, task IDs, and the target `content` (IP ranges, ports, CVE/fingerprint
   rules).
4. **Scan** — executes the task; the dmap fingerprint engine identifies specific services
   (e.g. Oracle WebLogic, Fortinet) by banner/protocol signature, not just open/closed
   ports.
5. **Report** — compresses and submits results (`/data/v2/pscan`); the loop repeats until
   the operator stops it.

## Intelligence value unlocked here

This repository **recovers the tasking-decryption scheme** (Tactical §3). Operationally,
that means: **if you capture a `probe_task` body, you can read what JDY is being tasked to
scan** — the adversary's targeting, in plaintext. That is a rare window into
exposure-discovery *before* the exploitation phase. Prioritize any capture pipeline that
can lawfully obtain that traffic.

## Infrastructure status (bounded)

The control cluster is **fully enumerated and bounded** by identity-grade anchors. The
`jdyfj` TLS certificate and the payload host's listener fingerprint each resolve to only
the known nodes — **no un-reported infrastructure** was found across FOFA/Netlas/Shodan/
Censys + the live Lumen IOC set. The operators rotate IPs/hosting freely but **do not
rotate the keypair**, which is why the cert remains a durable pivot. Full reasoning:
[`docs/INFRASTRUCTURE.md`](../docs/INFRASTRUCTURE.md).

## Collection guidance

- **Pivot on identity, not co-residency.** The `jdyfj` cert (and the Platypus + Acme Co
  listener combo for the payload host) are the reliable selectors. Shared hosting / VPS
  co-tenancy manufactures false overlaps — see the EXCLUDED set before acting on any VT
  relation.
- **Track rotation, not just current IPs.** Nodes age out and get re-leased to unrelated
  tenants; treat a rotated IP as stale, not a lead.
- **Watch the NOVEL endpoint** `POST /dispatch_service/v2/test` as a possible variant
  discriminator — if it appears on samples outside the published hash set, escalate.

## ATT&CK mapping (selected)

| Tactic | Technique |
|---|---|
| Reconnaissance | Active Scanning (T1595), Gather Victim Network Info (T1590) |
| Resource Development | Compromise Infrastructure: Botnet (T1584.005) |
| Initial Access (recruitment) | Exploit Public-Facing Application (T1190) |
| Command & Control | Proxy: Multi-hop / Tor (T1090), Encrypted Channel (T1573) |
| Defense Evasion | Indicator Removal: File Deletion (T1070.004) |

---

# 3. Tactical — for SOC, hunt, and detection engineering

## Highest-value hunt signals

These are behavioral and identity markers, robust to IP rotation:

| Signal | Value |
|---|---|
| **TLS cert** `jdyfj`, SHA-256 `2b640582…432cf` | identity-grade C2 selector |
| **SYN scan** fixed source port **19000**, incrementing dest ports | distinctive scan fingerprint |
| **ICMP probe** id **19037**, seq **35765** | distinctive probe fingerprint |
| Dispatch URIs `/dispatch_service/v2/probe_status`, `/probe_task`, **`/test`** (NOVEL) | C2 protocol strings |
| Result submit `POST /data/v2/pscan` | exfil/report path |
| **Platypus** mgmt port **13339** | payload-host fingerprint (with Acme Co Go-TLS :9960–9964) |
| Version string `1.8.3.9`; usage `-g <group_id> -s <web_ip>` | implant strings |

## Known infrastructure (current / live)

```
216.173.65[.]250    C2   (Evoxt,  Present)
194.14.217[.]88     C2   (M247 RO, Present)
149.248.3[.]38      Payload/tasking (Vultr LA, Present)
```

Aged-out C2 (`23.27.120[.]240`, `109.104.154[.]116`, last-seen 2026-03-21) and historical
`140.82.23[.]123` retained for retro-hunt only. Full IOC set with hashes:
[`iocs/JDY_IOCs.md`](../iocs/JDY_IOCs.md).

## Decrypting captured tasking

If you obtain a `probe_task` / `content` blob (base64), decrypt it to read the targeting:

```bash
python3 tools/jdy_decrypt.py task.b64
```

Scheme (full detail in [`docs/TECHNICAL_WRITEUP.md`](../docs/TECHNICAL_WRITEUP.md)):

```
chain : base64 (standard +/) -> AES-128-CBC decrypt -> JSON
key   : bdb718bdf47cbcde     (16 ASCII bytes, raw)
IV    : 0x30 x16             (ASCII '0'; fallback 0x00 x16, auto-detected)
fields: scan_type, task_id, sub_task_id, content (IP ranges, ports, CVEs)
```

The tool fails **loud** on bad PKCS#7 — if that happens, suspect the input (wrong field /
HTTP framing left on the blob), not the scheme.

## Triage discipline (avoid the co-residency trap)

JDY nodes sit on shared VPS/hosting; VT "relations" are mostly co-tenant noise. Run exports
through the tagger before acting:

```bash
python3 tools/vt_triage.py vt_export.csv --review-only
```

It checks JDY IOCs **first** (so a real node is never auto-excluded), tags CDN/cloud/RFC1918
as co-residency, auto-excludes known co-tenant domains (`faucetpot.xyz`, `oakenfjrod.ru`,
`gerenciadores.com`), and fails **open** to a REVIEW worklist. Reminders that matter:

- **Windows PE files in an IP's relations cannot be JDY** — the implant is MIPS ELF
  (architecture mismatch = exclude).
- A **rotated IP** re-leased to another tenant is stale, not a hit.

## Defensive actions (perimeter)

- **Accelerate patching** of internet-facing edge devices on disclosure, ahead of SLA.
- **Reduce attack surface:** disable unnecessary internet-exposed admin interfaces,
  restrict remote management, replace default credentials.
- **Monitor for unusual outbound scanning** originating from edge devices (a compromised
  SOHO box becomes a scanner).
- **Reboot + update** routers/firewalls/IoT regularly; prioritize replacing **EOL** edge
  hardware.

## Detection-rule note

No prebuilt rules are shipped (by design). The signals above — source port 19000, ICMP
id 19037, the dispatch URIs, the `jdyfj` cert — are sufficient to author network/host rules
locally if your environment requires them.

---

## Sources & caveats

Lumen Black Lotus Labs (June 2026) and `JDY_6_2026_IOCs.txt`; Censys (Feb 2026, independent
`jdyfj` cert tracking); DCSO CyTec (Tor administration); MITRE ATT&CK G1017. RE and
infrastructure analysis are original to this repository. AI assistance was used; all
outputs were treated as leads and reproduced against primary evidence before acceptance.
Estimative language follows ICD-203. Independent analysis, provided as-is for defensive
purposes.

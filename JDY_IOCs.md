# JDY — Consolidated IOCs

Indicators for the JDY botnet (China-nexus reconnaissance capability, KV/JDY lineage,
MITRE **G1017**). Source-tagged: **PUBLISHED** = in Lumen `JDY_6_2026_IOCs.txt`;
**NOVEL** = recovered in this analysis; **EXCLUDED** = co-residency/co-tenant noise
resolved with primary evidence.

**TLP:CLEAR.** Defanged. AI-assisted analysis; outputs reproduced against primary
evidence before acceptance.

---

## Network — control infrastructure (PUBLISHED + CORROBORATED)

| Indicator | First / Last Seen | Role |
|---|---|---|
| `216.173.65[.]250` | 2026-03-31 / Present | C2 (Evoxt) |
| `194.14.217[.]88` | 2026-03-31 / Present | C2 (M247 RO) |
| `23.27.120[.]240` | 2025-04-11 / 2026-03-21 | C2 (Evoxt, aged out) |
| `109.104.154[.]116` | 2025-04-11 / 2026-03-21 | C2 (BrainStorm NL, aged out) |
| `149.248.3[.]38` | 2025-06-06 / Present | Payload / tasking server (Vultr LA) |
| `140.82.23[.]123` | 2023 (historical) | C2 (Vultr, rotated) |

## TLS certificate — identity anchor (PUBLISHED)

| Type | Value |
|---|---|
| SHA-256 | `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf` |
| CN | `jdyfj` |
| Serial | `12362189573138375665` |
| First seen | 2023-11-14 |

## File hashes — SHA-256 (PUBLISHED)

**Payloads (MIPS / MIPS64 / MIPSEL):**
```
40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed   (analyzed sample)
28a23ab78739de674f94d9acadfe0709862c2b2d947e9051b200a24d3f9f45c4
d1414803a83b1ba260e3e1be742379eccbb806f987ec1e7c0bc5399e4971a58f
```
**Droppers (bash):**
```
03c4667f016f1e8441177639d87f77a59f32d2c7e0041616376967338667bd3b
1e0da906811b570c4134ade310c3a94631d4b308d27b616497266b49aae2ad0a
d62055910cd579ff1fb57bd1926c5b2e80e1677f0316737b2f733f86b01615dc
```
**Platypus / Termite client:**
```
96ecc107aa645e36b5f939ebfcf9e61fc9ebc27616680fbd0fdeb41c7950d79a
```

## Host / behavioral markers (PUBLISHED)

| Marker | Value |
|---|---|
| Version string | `1.8.3.9` |
| Architectures | MIPS, MIPS64, MIPSEL, MIPSEL64 (big + little endian) |
| Check-in | `POST /dispatch_service/v2/probe_status` |
| Tasking pull | `GET /dispatch_service/v2/probe_task/...` |
| Result submit | `POST /data/v2/pscan` |
| SYN scan | fixed source port **19000**, destination ports incremented |
| ICMP probe | id **19037**, seq **35765** |
| Platypus mgmt | port **13339** |
| Usage string | `usage:%s -g <group_id> -s <web_ip> [-l local_ip] [-c 0/1 check process]` |
| Tasking decode | base64 → AES → JSON (hardcoded key) |

---

## NOVEL — recovered in this analysis

| Indicator | Detail |
|---|---|
| **Tasking cipher** | AES-128-CBC, key `bdb718bdf47cbcde` (16 ASCII bytes, raw), IV `0x30`×16 |
| **Key decomposition** | published `0000000000000000bdb718bdf47cbcde` = IV `0000000000000000` ∥ KEY `bdb718bdf47cbcde` |
| **Third dispatch endpoint** | `POST /dispatch_service/v2/test` (not in public reporting) |
| **Build provenance** | Buildroot GCC 4.8.3; statically-linked OpenSSL; `MIPS:BE:64` |

---

## EXCLUDED — co-residency / co-tenant noise (primary-evidence resolved)

| Indicator | Why excluded |
|---|---|
| `45.63.60[.]39` | rotated away; now Windows RDP/WinRM, different tenant |
| `45.32.174[.]13` | rotated away; Brazilian shared-hosting reseller |
| `oakenfjrod[.]ru` | infostealer co-tenant on shared Evoxt VPS |
| `*.faucetpot[.]xyz` | shared cPanel co-tenant on `149.248.3.38` |
| `gerenciadores[.]com` | shared-hosting reseller co-tenant |
| `47.239.105[.]221` | Finstars fintech agent API (box's own JSON) |
| `162.159.36[.]2` | Cloudflare CDN co-residency |
| Windows PE relation files | wrong architecture — cannot relate to MIPS ELF |
| Sandbox detonation PCAP(s) | Windows-guest telemetry, arch-mismatched run |

---

## Detection note

No detection rules are included by default. The behavioral markers above (source port
19000, ICMP id 19037, the dispatch URIs, the `jdyfj` cert) are sufficient to author
network or host rules if required; the encrypted-tasking scheme in
[`docs/TECHNICAL_WRITEUP.md`](../docs/TECHNICAL_WRITEUP.md) supports decryption of captured
`probe_task` traffic for content-level triage.

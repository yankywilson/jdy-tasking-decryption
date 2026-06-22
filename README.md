# JDY Botnet — Tasking Decryption & Implant Analysis

Reverse engineering of the **JDY** botnet's encrypted dispatch tasking and implant
internals, plus a bounded enumeration of its control infrastructure. JDY is a China-nexus
reconnaissance capability of the **KV-botnet / Volt Typhoon** lineage (MITRE **G1017**),
re-detailed by Lumen Black Lotus Labs in June 2026.

This work recovers the tasking-decryption scheme at the instruction level, provides a
working decryptor, maps the implant's command-method dispatch, and independently confirms
the published control cluster is bounded.

**Classification:** TLP:CLEAR · ICD-203 estimative language · findings tagged
**NOVEL / CORROBORATED / PUBLISHED / EXCLUDED**.

---

## TL;DR

JDY bots pull scanning tasks from a Tor-hidden dispatch service. The tasking is
**base64 → AES → JSON**. Static RE of the primary MIPS64 payload recovers the exact
scheme:

- **AES-128-CBC**, decrypt
- **Key:** `bdb718bdf47cbcde` — 16 ASCII bytes, used raw (not hex-decoded)
- **IV:** 16 bytes of ASCII `0` (`0x30` × 16)
- The published "key" `0000000000000000bdb718bdf47cbcde` is **IV ∥ KEY**, not a 32-byte key.

`tools/jdy_decrypt.py` implements this and reads a captured `probe_task` body into the
plaintext tasking JSON — i.e. the IP ranges, ports, and CVE/fingerprint rules JDY is
pointed at.

Implant RE also shows JDY is **not a pure scanner**: the binary carries a `meth_tunnel`
command-method class and a full **SOCKS4/4a/5/5h** stack, indicating a tasked bot can
likely act as a **proxy / relay pivot** — extending the capability beyond reconnaissance.

The control cluster is **bounded**: the `jdyfj` self-signed TLS certificate and the
payload host's listener fingerprint each resolve to only the already-known nodes. No
un-reported infrastructure was found.

---

## Key findings

| Finding | Tag |
|---|---|
| Tasking scheme: base64 → **AES-128-CBC** → JSON, key `bdb718bdf47cbcde`, IV `0x30`×16 | **CORROBORATED** |
| **SOCKS tunnel / proxy-pivot capability** (`meth_tunnel` + SOCKS4/4a/5/5h) | **NOVEL** |
| Command-method dispatch: `meth_tcp` / `meth_udp` / `meth_ssl` / `meth_tunnel` | **CORROBORATED / NOVEL** |
| Scan-type vocabulary: `port_scan`, `web_scan`, `banner`, `tunnel`, `content` | **CORROBORATED / NOVEL** |
| Fingerprint-DB update via `/dispatch/v2/dmap/%s` (mmapped archive, `dmap_fp_digest`-gated) | **NOVEL** |
| Third dispatch endpoint `POST /dispatch_service/v2/test` | **NOVEL** |
| Dispatch tier: front-end **nginx/1.20.1** reverse-proxy → **Python (DRF/FastAPI)** backend | **NOVEL** |
| Scan engine: SYN source port **19000**, ICMP id **19037** | **CORROBORATED** |
| ICMP sequence reads **36765** in-binary (vs. 35765 in public reporting) — pending bench validation | **NOVEL — UNVALIDATED** |
| Control cluster bounded by `jdyfj` cert + payload-host fingerprint; Salt↔Volt link refuted | **EXCLUDED** |

---

## What's here

| Path | What |
|---|---|
| [`docs/INTELLIGENCE_REPORT.md`](docs/INTELLIGENCE_REPORT.md) | **Tiered intelligence report** — strategic (CISO/leadership), operational (TI/IR), tactical (SOC/hunt) |
| [`docs/TECHNICAL_WRITEUP.md`](docs/TECHNICAL_WRITEUP.md) | Full RE walkthrough: Ghidra anchors, the crypto call chain, the AES-128-vs-256 resolution, and the infrastructure pivots |
| [`docs/IMPLANT_COMPONENTS_RE.md`](docs/IMPLANT_COMPONENTS_RE.md) | Component RE: scan engine, command-method table, dmap update mechanism, and the tunnel capability |
| [`docs/INFRASTRUCTURE.md`](docs/INFRASTRUCTURE.md) | Cluster enumeration, cert pivot, payload-host fingerprint, exclusions worked with primary evidence |
| [`tools/jdy_decrypt.py`](tools/jdy_decrypt.py) | The tasking decryptor (AES-128-CBC; IV auto-detect; loud PKCS#7 failure; `--selftest`/`--demo`) |
| [`tools/vt_triage.py`](tools/vt_triage.py) | VirusTotal relation-export auto-tagger; collapses co-residency noise, IOC-first ordering |
| [`iocs/JDY_IOCs.md`](iocs/JDY_IOCs.md) | Consolidated IOC table with first/last-seen and per-claim tags |

---

## Quick start

```bash
# prove the decryptor end-to-end (no input needed)
python3 tools/jdy_decrypt.py --selftest
python3 tools/jdy_decrypt.py --demo

# decrypt a captured probe_task / "content" blob (base64 text)
python3 tools/jdy_decrypt.py task.b64

# triage a VirusTotal relation export (type,id CSV)
python3 tools/vt_triage.py vt_export.csv --review-only
```

Requirements: Python 3, `pycryptodome` (for `jdy_decrypt.py`). `vt_triage.py` is
stdlib-only.

---

## Scope & method

This is a **defensive** analysis. The investigation is passive-OSINT throughout;
binary work is bench RE on an isolated host. Every claim is tagged at the claim level,
and AI-assisted outputs were treated as leads requiring analyst reproduction before
acceptance. The decryptor was validated by round-trip against known plaintext, not by
assertion. Component-RE items still pending Ghidra confirmation are tagged
**NOVEL — UNVALIDATED** rather than asserted as fact.

A structural finding runs through the whole effort: **nation-state actors routinely
ride shared and commodity infrastructure** (shared hosting, reused VPS, off-the-shelf
tooling), which manufactures false overlaps. Those are resolved here with
**identity-grade anchors** — TLS keypairs and listener fingerprints — rather than IP or
domain co-residency.

---

## Attribution note

JDY is a **shared, multi-actor reconnaissance capability** of the KV/JDY lineage, used
to support China-nexus operations including Volt Typhoon. Because shared infrastructure
caps attribution confidence, this analysis frames JDY as a *China-nexus reconnaissance
capability* rather than asserting single-actor ownership. See
[`docs/INFRASTRUCTURE.md`](docs/INFRASTRUCTURE.md) for the reasoning.

---

## Credits & references

- Lumen Black Lotus Labs — *Expanded JDY IoT and SOHO botnet enables rapid vulnerability
  exploitation* (June 2026) and the `blacklotuslabs/IOCs` repo (`JDY_6_2026_IOCs.txt`).
- Censys — *Will the Real Volt Typhoon Please Stand Up?* (Feb 2026), independent tracking
  of the `jdyfj` certificate.
- DCSO CyTec — JDY Tor-administration analysis.
- MITRE ATT&CK — Volt Typhoon (G1017).

Independent analysis. Not affiliated with or endorsed by the above. Provided as-is for
defensive purposes.

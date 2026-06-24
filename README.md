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

The control cluster is **bounded**: the `jdyfj` self-signed TLS certificate and the
payload host's listener fingerprint each resolve to only the already-known nodes. No
un-reported infrastructure was found.

---

## Key findings

| Finding | Tag |
|---|---|
| Tasking scheme: base64 → **AES-128-CBC** → JSON, key `bdb718bdf47cbcde`, IV `0x30`×16 | **CORROBORATED** |
| Command-method dispatch: `meth_tcp` / `meth_udp` / `meth_ssl` / `meth_tunnel` | **CORROBORATED / NOVEL** |
| Scan-type vocabulary: `port_scan`, `web_scan`, `banner`, `tunnel`, `content` | **CORROBORATED / NOVEL** |
| Fingerprint-DB update via `/dispatch/v2/dmap/%s` (mmapped archive, `dmap_fp_digest`-gated) | **NOVEL** |
| Third dispatch endpoint `POST /dispatch_service/v2/test` | **NOVEL** |
| Dispatch tier: front-end **nginx/1.20.1** reverse-proxy → **Python (DRF/FastAPI)** backend | **NOVEL** |
| Scan engine: SYN source port **19000**, ICMP id **19037** | **CORROBORATED** |
| ICMP sequence reads **36765** in-binary (vs. 35765 in public reporting) — pending bench validation | **NOVEL — UNVALIDATED** |
| Control cluster bounded by `jdyfj` cert + payload-host fingerprint; Salt↔Volt link refuted | **EXCLUDED** |



- DCSO CyTec — JDY Tor-administration analysis.
- MITRE ATT&CK — Volt Typhoon (G1017).

Independent analysis. Not affiliated with or endorsed by the above. Provided as-is for
defensive purposes.

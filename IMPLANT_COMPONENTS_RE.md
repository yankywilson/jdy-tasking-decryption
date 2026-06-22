# JDY Implant — Component RE Addendum (Scan Engine, Command Dispatch, dmap, Tunnel)

**Sample:** `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`
(ELF 64-bit MSB MIPS64, statically linked, stripped — in Lumen `JDY_6_2026` IOCs)
**Scope:** Extends the tasking-decryption RE into the scan engine, command-method table,
fingerprint-DB update mechanism, and a previously-undocumented tunnel capability.
**Method:** Static analysis (`mips-linux-gnu-objdump`, `.rodata` string/xref mapping) in an
isolated Linux container. **AI-assisted; all findings are leads requiring analyst
reproduction in Ghidra on the bench before assertion.**
**Tagging:** NOVEL / CORROBORATED / PUBLISHED / EXCLUDED, ICD-203 estimative language.

---

## 1. Scan engine (Target 3)

Confirmed directly from immediate loads in `.text`:

| Field | Value | Evidence | Tag |
|---|---|---|---|
| SYN source port | **19000** | `li v0,19000` at `0x1000f328` and `0x1001f204`, stored as halfword into a stack `sockaddr_in` (network order), followed by a hardcoded `sin_addr` | **CORROBORATED** |
| ICMP identifier | **19037** | `li v0,19037` at `0x1001ef7c`, single site, stored as halfword into the ICMP packet buffer | **CORROBORATED** |
| ICMP sequence | **see caveat** | the halfword stored immediately after the id (buffer +18) is `0x8f9d` = **36765**, **not** the `35765`/`0x8bb5` in public reporting | **NOVEL — UNVALIDATED** |

**The SYN source port is the strongest scan-engine anchor.** It is loaded identically in two
separate scan paths and written into a `sockaddr_in` structure, which confirms it is a real
fixed source port, matching Lumen's port-19000 SYN fingerprint.

**ICMP sequence discrepancy — flagged, not asserted.** The binary's single load of the
halfword at the sequence-field position is `0x8f9d` (36765). The value `0x8bb5` (35765) does
not appear anywhere in the binary. This is assessed as **possibly** a variant-specific value
or **possibly** an artifact of flat-disassembly offset reading (the ICMP buffer's exact field
boundaries could not be fully resolved without xref/type reconstruction).

> **Bench action (Ghidra):** anchor on `li v0,19037` at `0x1001ef7c`, decompile the enclosing
> function, and read the `icmphdr` struct to confirm whether buffer +18 is the sequence field
> and whether `0x8f9d` is the transmitted sequence. Resolve before publishing the seq value.

---

## 2. Command-method dispatch table (Target 4)

The command dispatcher is **not** a flat switch — it is a set of **C++ polymorphic method
classes** (recovered from mangled class names in `.rodata`). A tasking's `scan_type` selects
the concrete method.

| Method class | VA | Capability | Tag |
|---|---|---|---|
| `meth_des` | `0x10245ef8` | method-descriptor base (dispatcher) | structural |
| `meth_tcp` | `0x10245ff8` | TCP probe | **CORROBORATED** |
| `meth_udp` | `0x10246008` | UDP probe | **CORROBORATED** |
| `meth_ssl` | `0x10246018` | SSL/TLS probe | **CORROBORATED** |
| `meth_tunnel` | `0x10245fe8` | **SOCKS tunnel / proxy pivot** | **NOVEL** |
| `meth_package` | `0x10245578` | base wire-format builder | structural |
| `meth_package_http` | `0x10245560` | HTTP request builder | **NOVEL** detail |
| `meth_package_raw` | `0x10245588` | raw packet builder | **NOVEL** detail |

**Scan-type vocabulary** (the values `scan_type` takes), from `.rodata`:

| Value | VA | Meaning | Tag |
|---|---|---|---|
| `port_scan` | `0x102451c8` | TCP/SYN port scan | **CORROBORATED** |
| `web_scan` | `0x102451d8` | HTTP/web service scan | **NOVEL** |
| `banner` | `0x10245290` | banner grab | **CORROBORATED** |
| `tunnel` | `0x10245288` | tunnel/relay | **NOVEL** |
| `content` | `0x10245298` | response/content capture | **NOVEL** |

> **Bench action:** the string→method xrefs are GOT/`gp`-relative and were not resolvable by
> flat objdump grep. In Ghidra, xref each `scan_type` value string to recover the exact
> dispatcher comparison chain and bind each string to its `meth_*` handler.

---

## 3. Tunnel / proxy capability (NOVEL — threat-model impact)

**Finding:** the implant is not a pure passive scanner. `0x10245fe8` carries the mangled
class `meth_tunnel`, and the binary statically links a full SOCKS stack:

```
socks5h, socks5, socks4a, socks4   (0x10246370–0x10246390)
"Unsupported proxy scheme for '%s'", NO_PROXY/ALL_PROXY handling
```

**Assessment:** it is **likely** that a tasked JDY bot can be directed to operate as a
**SOCKS proxy / relay pivot**, tunneling operator traffic through the compromised edge device.
This materially extends the capability beyond reconnaissance into **operational relay**, and
is consistent with the broader pattern of nation-state actors using SOHO botnets as
traffic-obfuscation infrastructure.

> **Bench action:** confirm the `meth_tunnel` method is reachable from the tasking dispatcher
> (not dead/inherited code) and identify which `scan_type`/command value selects it.

---

## 4. dmap fingerprint-DB update (how rapid CVE-targeting works)

The `update_dmap_fp_db` command pushes new service-detection rules to the bot:

| Artifact | VA | Role |
|---|---|---|
| `update_dmap_fp_db` | `0x10245a58` | command name |
| `/dispatch/v2/dmap/%s` | `0x10245a70` | fingerprint-archive fetch URI |
| `dmap_fp_digest` | `0x10245610` | local DB version hash (sent to C2) |
| `headmap.len == archive_stat.st_size` | (assert) | downloaded archive is **mmapped** |

**Mechanism (assessed):** the bot reports its `dmap_fp_digest`; if stale, it fetches a
fingerprint archive from `/dispatch/v2/dmap/<id>`, which it memory-maps (the
`headmap`/`archive_stat` assertions confirm file-backed mmap). This is the delivery path that
lets operators **update what services/CVEs the fleet recognizes without redeploying the
implant** — the mechanism behind JDY's observed rapid pivoting to new vulnerabilities.

---

## 5. NOVEL URI namespace

`0x102451b8` carries **`/dispatch/v2`** — a shorter dispatch base path distinct from the
documented `/dispatch_service/v2`. The dmap URI (`/dispatch/v2/dmap/%s`) and `/wscan`
(`0x102451e8`) hang off this shorter namespace. **NOVEL** — not in Lumen reporting; log as an
additional dispatch-URI family for hunting.

---

## 6. Tasking / registration schema (CORROBORATED + detail)

Registration JSON, in the clear at `0x10245078`:

```json
{"prober":{"v":"%s","ip":"%s","mac":"%s"},"task":{"v":%d}}
```

Result submission path: `POST /data/v2/pscan` (`0x102450e0`), carrying `task_list` /
`banner_list` arrays (`0x10245048` / `0x10245060`) assembled by the `rsp_package` /
`scan_rsp_queue` classes.

**AES key/IV confirmed adjacent in `.rodata`** (re-confirms the decryption recovery):
`bdb718bdf47cbcde` at `0x10245160`, `0000000000000000` at `0x10245178` → the published
`0000000000000000bdb718bdf47cbcde` is **IV ∥ KEY**. **CORROBORATED.**

---

## 7. Honest limits of this pass

- **The dropper is NOT in this binary.** It is a separate bash script (per Lumen); the
  `/tmp/%s`, `/proc/%d/%s`, and libcurl strings here are the **implant's own** runtime, not the
  dropper. Dropper RE requires sourcing that script separately. **Not analyzable from this
  file.**
- **String→code xrefs were GOT/`gp`-relative** and not fully resolvable with flat objdump;
  the command-method bindings and the ICMP seq field need **Ghidra** to confirm.
- **Every value here is a lead.** The high-confidence items (port 19000, ICMP id 19037, the
  `meth_*` class names, the dmap URI, the key/IV adjacency) are direct `.rodata`/immediate
  reads. The seq value and the tunnel reachability are **explicitly flagged for bench
  validation** before any of it is published or fed into detection.

---

*Independent defensive analysis. AI-assisted; provided as leads for analyst reproduction.
TLP:CLEAR.*

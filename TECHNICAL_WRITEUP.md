# JDY Tasking Decryption — Technical Writeup

Recovering the JDY botnet's dispatch-tasking cipher from the MIPS64 implant, and
building a decryptor that reads the targeting JSON directly.

**TLP:CLEAR** · ICD-203 estimative language · findings tagged **NOVEL / CORROBORATED /
PUBLISHED / EXCLUDED**.

---

## 1. Why decrypt the tasking

Every passive layer of JDY is already mapped or proven invisible: the relay nodes are
enumerated, the payload host is identified, the dispatch C2 is Tor-hidden, and the bot
fleet does quiet SYN reconnaissance that is not passively separable. The remaining
intelligence is not a *who* (which IP) but a *what* — **what JDY is tasked to scan.**
That lives only inside the encrypted tasking the implant pulls from its dispatch service.

As one analyst framed the broader shift: exploitation no longer begins when malicious
code arrives, it begins when exposure is discovered. Reading JDY's decrypted tasking is
reading exposure-discovery in real time — the IP ranges, ports, and CVE/fingerprint rules
the operators are pointed at, before the follow-on exploitation phase.

So the objective is narrow and high-value: **recover the tasking-decryption scheme, then
read a captured `probe_task` body.**

---

## 2. The sample

**SHA-256** `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed` — listed as
a JDY payload in Lumen's `JDY_6_2026_IOCs.txt`. **CORROBORATED** as the real implant: it
carries the full set of published JDY markers (the `dispatch_service` URIs, version
`1.8.3.9`, the `usage:%s -g <group_id> -s <web_ip>` string, `report_status`,
`update_dmap_fp_db`).

**File triage (Detect-It-Easy + `readelf` + `file`, three-way agreement):**

| Property | Value |
|---|---|
| Format | ELF 64-bit **MSB** (big-endian) |
| Arch | **MIPS64** (R3000 / mips64 flags) |
| Linking | statically linked, stripped |
| Toolchain | Buildroot GCC 4.8.3 |
| Crypto | statically-linked OpenSSL |

**Correction logged:** the Triage sandbox tagged the guest `debian9-mipsbe` (32-bit),
which is why a detonation produced `exec format error` — a **64-bit** binary cannot run on
a 32-bit guest. The correct Ghidra load language is **`MIPS:BE:64`**, confirmed by all
three triage tools. This mislabel is the kind of environment artifact that derails
analysis if taken at face value; it is noted here as a caveat for anyone re-running.

**EtherHiding EXCLUDED from the binary** — grep for on-chain/EtherHiding markers returns
nothing; JDY's tasking is HTTP-over-TLS to a dispatch service, not blockchain-brokered.

---

## 3. Ghidra anchors

Five landmarks make the disassembly legible. The implant is PIC and uses `gp`-relative
loads; Ghidra resolves `gp = 0x1030c050` at entry, which lets the constant-reference
analyzer recover the string and table loads.

| Address | Label | Sanity check |
|---|---|---|
| `0x10245160` | key half A | ASCII `bdb718bd` |
| `0x10245168` | key half B | ASCII `f47cbcde` |
| `0x10245000` | base64 alphabet | `ABCD…+/` (standard) |
| `0x10260800` | AES `Td0` (decrypt table) | bytes `51 f4 a7 50…` |
| `0x103084f0` | `Td0` GOT slot (`gp-0x3b60`) | pointer → `0x10260800` |

**Note on the key layout:** the key is stored as two adjacent 8-byte ASCII strings,
`bdb718bd` at `0x10245160` and `f47cbcde` at `0x10245168`. Ghidra's xref column shows both
halves, the base64 alphabet, and the dispatch URIs are all referenced by a single
function — `FUN_10007da0` — which is therefore the **tasking wrapper** (the function that
runs the whole `fetch → base64 → AES → JSON → pscan` loop). The crypto was located on the
first landmark, by xref, because everything clusters in one function.

---

## 4. The crypto call chain

Traced from the decrypt table out to the wrapper:

```
Td0 GOT slot (0x103084f0)
  → AES_decrypt (references Td0 0x10260800)
    → FUN_1009ce80   CBC decrypt loop  (per-block XOR + chaining)
      → FUN_1009bf68   enc-flag dispatcher  (enc=0 → decrypt)
        → FUN_1009bf34   key schedule  (bits arg)
          → FUN_10007da0   tasking wrapper  (base64 → AES → JSON)
```

### 4.1 The key/IV setup

Inside `FUN_10007da0`, the stack buffers are built with four 8-byte writes immediately
before the crypto calls (decompiler view):

```c
local_170    = 0x6264623731386264;            // "bdb718bd"  (8 bytes, BE)
local_168[]  = 'f','4','7','c','b','c','d','e' // "f47cbcde"
local_180[]  = '0' × 8                          // "00000000"
local_178[]  = '0' × 8                          // "00000000"

FUN_1009bf34(&local_170, 0x80, &sched);                     // key schedule, bits = 0x80
FUN_1009bf68(&out, &in, 0x1000, &sched, local_180, 0);      // CBC, enc = 0 (decrypt)
```

### 4.2 Resolving AES-128 vs AES-256 (the trap)

The published "key" is `0000000000000000bdb718bdf47cbcde` — 32 hex characters. The naive
reading is *32 ASCII bytes → AES-256*. The instruction-level evidence says otherwise:

- The **key-schedule call passes `0x80` (= 128)** as the bits argument. This is read
  directly off `$a1` (the n64 ABI second argument) before the `jal`, delay-slot aware.
- The **key buffer is the 16 ASCII bytes** `bdb718bdf47cbcde` — half A ∥ half B. It is
  used **raw**, not hex-decoded.
- The two `"00000000"` buffers are **not key material** — they are the **IV**.

So the published 32-hex string decomposes as:

```
0000000000000000   →  IV  (16 ASCII '0' bytes, 0x30 × 16)
bdb718bdf47cbcde   →  KEY (16 ASCII bytes, AES-128)
```

**The leading hypothesis (AES-256 from 32 ASCII bytes) was wrong; the binary says
AES-128.** This is exactly why the scheme was read at the instruction level rather than
inferred from the IOC string.

### 4.3 Confirming the mode is CBC

`FUN_1009bf68` is a thin dispatcher — branch on the enc flag, select one of two workers:

```c
void FUN_1009bf68(void) {
  if (in_t1 == 0)  pcVar1 = FUN_1009ce80;   // enc == 0 → DECRYPT worker
  else             pcVar1 = FUN_1009cca0;   // encrypt worker
  (*pcVar1)();
}
```

That branch-on-flag-then-call-block-function shape **is** OpenSSL's `AES_cbc_encrypt`.
The call passed `enc=0`, so it takes `FUN_1009ce80`. Reading that worker confirms textbook
CBC decryption: the block-decrypt function pointer is invoked once per 16-byte block,
then the output is **XOR'd with the previous ciphertext block** and the **current
ciphertext block is saved as the next IV** (16-byte stride, residual-block handling at the
tail, last cipher block written back to the IV buffer). The CBC chaining math only works
if that function pointer returns a decrypted block — i.e. it is `AES_decrypt`, the one
that walks `Td0`. The identification is therefore proven by what the loop does with the
output, not assumed.

### 4.4 The IV nuance

The IV is **16 bytes of ASCII `0`** (`0x30` × 16), sourced from the `"00000000"` buffers —
not null bytes, not derived from `probe_id`, not prepended to the ciphertext. A decompiler
may render these as `0x30`; the implant could in principle fall back to `0x00` × 16. Since
CBC only XORs the IV into the **first** block, a wrong IV corrupts block 1 only and leaves
blocks 2+ as clean JSON — a single-block tell. The decryptor handles both variants (see
§5).

---

## 5. The decryptor

[`tools/jdy_decrypt.py`](../tools/jdy_decrypt.py) implements the recovered scheme:

| Parameter | Value |
|---|---|
| Algorithm | AES-128-CBC, decrypt |
| Key | `bdb718bdf47cbcde` (16 ASCII bytes, raw) |
| IV | `0x30` × 16 primary; `0x00` × 16 fallback (auto-detected) |
| Front end | standard base64 (`+/`) |
| Chain | base64 → AES-128-CBC → JSON (`scan_type`, `task_id`, `sub_task_id`, `content`) |

Design choices that encode the analysis discipline:

- **IV auto-detect.** Tries `0x30` × 16, then `0x00` × 16, and picks the JSON-valid
  result — resolving the §4.4 nuance at runtime rather than guessing.
- **Loud PKCS#7 failure.** If padding doesn't validate, the tool reports which IV was
  tried and stops, telling you the input is likely **not the raw AES blob** (wrong field /
  HTTP framing left on it) rather than that the scheme is wrong. This is the
  provenance guardrail: suspect *what you fed in* before suspecting the cipher.
- **Block-alignment check.** Catches "this base64 isn't the ciphertext" before chasing a
  phantom.
- **`--selftest` / `--demo`.** Round-trip against known plaintext, so the wiring can be
  re-verified anywhere with no input file.

The decryptor was validated end-to-end: a tasking blob encrypted with the recovered
scheme decrypts back to its source JSON, and `--demo` shows the targeting fields
(`scan_type`, `task_id`, `sub_task_id`, and a `content` target list such as
`198.51.100.0/24:443,8443; CVE-2026-35616`) extracted from ciphertext. The full
`base64 → AES → JSON → target-list` loop is proven offline.

**Outstanding:** a *live* `probe_task` ciphertext to run through the tool. Eliciting one
requires running the MIPS64-BE implant in an emulator against a **sinkhole** C2 (the
implant must never reach the real JDY dispatch service). The decryptor is ready; when a
real blob is captured, `python3 jdy_decrypt.py <blob.b64>` reads the tasking.

---

## 6. NOVEL finding — a third dispatch endpoint

Beyond the two published dispatch URIs (`probe_status`, `probe_task`), the implant
contains a third:

```
POST /dispatch_service/v2/test
```

This endpoint is **not present in Lumen's reporting** and was not found in any other
public source during this analysis. **NOVEL.** It appears in the wrapper's reporting path
and is a candidate version discriminator — if it surfaces on samples outside the published
hash set, that would indicate a new variant.

---

## 7. What's confirmed

| Claim | Tag |
|---|---|
| Sample is the real JDY implant (markers present) | CORROBORATED |
| Arch is MIPS64 big-endian (`MIPS:BE:64`) | CORROBORATED |
| Tasking = base64 → AES-128-CBC → JSON | **NOVEL** (recovered by RE) |
| Key `bdb718bdf47cbcde`, 16 ASCII bytes, raw | **NOVEL** |
| IV = `0x30` × 16 (published key is IV ∥ KEY) | **NOVEL** |
| `POST /dispatch_service/v2/test` endpoint | **NOVEL** |
| EtherHiding present in binary | EXCLUDED |
| Triage `debian9-mipsbe` 32-bit guest tag | EXCLUDED (mislabel) |

---

## 8. Reproduction notes

- Load `40ad28b8…` in Ghidra as **`MIPS:BE:64`**, default compiler, full auto-analysis
  with the MIPS constant-reference analyzer enabled.
- Drop the five landmarks (§3), then follow the `Td0` GOT-slot xref into `AES_decrypt`,
  and the key-half xrefs into `FUN_10007da0`.
- Read the bits argument off `$a1` before the key-schedule `jal` (delay-slot aware), and
  confirm `FUN_1009bf68 → FUN_1009ce80` is the CBC worker by the XOR-prev / save-IV shape.
- Validate with `jdy_decrypt.py --selftest` before trusting output on a real blob.

AI assistance was used during analysis; all outputs were treated as leads and reproduced
against the binary before acceptance.

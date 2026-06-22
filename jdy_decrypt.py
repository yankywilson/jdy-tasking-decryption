#!/usr/bin/env python3
"""
jdy_decrypt.py - JDY botnet tasking decryptor (Phase 4).

Recovered scheme (from static RE of payload 40ad28b8..., function FUN_10007da0):
    chain : base64(standard +/) -> AES-128-CBC decrypt -> JSON
    key   : "bdb718bdf47cbcde"  (16 ASCII bytes, used RAW - not hex-decoded)
    IV    : 16 bytes, ASCII '0' (0x30 x16)   [primary]
            or 16 NUL bytes (0x00 x16)        [fallback - see --iv]
    pad   : PKCS#7 (validated; failure is loud)

The published "key" 0000000000000000bdb718bdf47cbcde decomposes as:
    IV  = 0000000000000000   (the leading half)
    KEY = bdb718bdf47cbcde   (the trailing half, the real AES key)

USAGE
  # decrypt a captured probe_task / "content" blob (base64 text)
  python3 jdy_decrypt.py <blob.b64>
  echo '<base64...>' | python3 jdy_decrypt.py -          # from stdin
  python3 jdy_decrypt.py --b64 '<base64...>'             # inline

  # IV control (default tries 0x30x16, then 0x00x16 automatically)
  python3 jdy_decrypt.py blob.b64 --iv zero    # force 0x00 x16
  python3 jdy_decrypt.py blob.b64 --iv ascii   # force 0x30 x16
  python3 jdy_decrypt.py blob.b64 --iv auto    # default: try both

  # self-test (no input needed) - proves the cipher path end to end
  python3 jdy_decrypt.py --selftest

NOTES
  - On bad PKCS#7 padding the tool reports WHICH iv was tried and stops,
    so you can tell wrong-IV / wrong-ciphertext from a wrong-scheme.
  - If block 1 is garbage but blocks 2+ are clean JSON, the IV is the
    other variant (CBC only XORs the IV into the first block). --iv auto
    detects this by trying both and picking the JSON-valid result.
"""

import argparse
import base64
import json
import sys

from Crypto.Cipher import AES

KEY = b"bdb718bdf47cbcde"          # 16 ASCII bytes, raw
IV_ASCII = b"0" * 16               # 0x30 x16
IV_ZERO = b"\x00" * 16             # 0x00 x16
BLOCK = 16


# ---------- core ----------

def _pkcs7_strip(data: bytes) -> bytes:
    """Validate + strip PKCS#7. Raises ValueError on bad padding."""
    if not data or len(data) % BLOCK != 0:
        raise ValueError(f"ciphertext not block-aligned ({len(data)} bytes)")
    pad = data[-1]
    if pad < 1 or pad > BLOCK:
        raise ValueError(f"bad pad byte 0x{pad:02x}")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("pad bytes inconsistent")
    return data[:-pad]


def decrypt_once(ct: bytes, iv: bytes, strip_pad: bool = True) -> bytes:
    if len(ct) % BLOCK != 0:
        raise ValueError(f"ciphertext not 16-byte aligned ({len(ct)} bytes) "
                         f"- is this really the raw AES blob?")
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    return _pkcs7_strip(pt) if strip_pad else pt


def _looks_like_json(b: bytes) -> bool:
    s = b.lstrip()
    return s[:1] in (b"{", b"[")


def decrypt_auto(ct: bytes):
    """Try ASCII-'0' IV then NUL IV. Return (plaintext, iv_label, json_ok)."""
    attempts = [("ascii (0x30 x16)", IV_ASCII), ("zero (0x00 x16)", IV_ZERO)]
    last_err = None
    # First pass: require valid padding AND JSON-looking output.
    for label, iv in attempts:
        try:
            pt = decrypt_once(ct, iv, strip_pad=True)
            if _looks_like_json(pt):
                return pt, label, True
        except ValueError as e:
            last_err = e
    # Second pass: accept valid padding even if not obviously JSON.
    for label, iv in attempts:
        try:
            pt = decrypt_once(ct, iv, strip_pad=True)
            return pt, label, _looks_like_json(pt)
        except ValueError as e:
            last_err = e
    raise ValueError(f"both IVs failed PKCS#7 validation; last error: {last_err}")


# ---------- input handling ----------

def load_b64(arg_b64, path):
    if arg_b64 is not None:
        raw = arg_b64
    elif path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, "r") as fh:
            raw = fh.read()
    raw = "".join(raw.split())          # drop whitespace/newlines
    if not raw:
        raise ValueError("no base64 input provided")
    try:
        return base64.b64decode(raw, validate=False)
    except Exception as e:
        raise ValueError(f"base64 decode failed: {e}")


def emit(pt: bytes, iv_label: str, json_ok: bool):
    print(f"[+] AES-128-CBC decrypt OK  (IV: {iv_label})")
    print(f"[+] plaintext: {len(pt)} bytes\n")
    if json_ok:
        try:
            obj = json.loads(pt)
            print(json.dumps(obj, indent=2, ensure_ascii=False))
            # quick targeting summary if the expected fields are present
            keys = obj.keys() if isinstance(obj, dict) else []
            hot = [k for k in ("scan_type", "task_id", "sub_task_id",
                               "task_list", "content") if k in keys]
            if hot:
                print("\n[+] tasking fields present:", ", ".join(hot))
            return
        except json.JSONDecodeError as e:
            print(f"[!] looked like JSON but failed to parse: {e}\n")
    # not JSON (or parse failed): dump safely
    try:
        print(pt.decode("utf-8"))
    except UnicodeDecodeError:
        print("[!] non-UTF8 plaintext; hex follows:\n")
        print(pt.hex())


# ---------- self test ----------

def selftest():
    """Encrypt a known tasking JSON with the recovered scheme, then decrypt
    it back through the real code path. Proves cipher/pad/base64 wiring."""
    from Crypto.Util.Padding import pad
    sample = {
        "scan_type": "port_scan",
        "task_id": "T-2026-0001",
        "sub_task_id": "S-01",
        "content": "203.0.113.0/24:443,8443; CVE-2026-35616",
    }
    plain = json.dumps(sample).encode()
    ok = True
    for label, iv in [("ascii (0x30 x16)", IV_ASCII), ("zero (0x00 x16)", IV_ZERO)]:
        ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(plain, BLOCK))
        blob = base64.b64encode(ct)
        # round-trip through the public path
        raw = base64.b64decode(blob)
        pt, used, jok = decrypt_auto(raw)
        match = (json.loads(pt) == sample)
        ok = ok and match and jok
        print(f"[selftest] IV={label:18s} encrypt->b64->decrypt  "
              f"detected_iv={used:18s} json_ok={jok} match={match}")
    print("\n[selftest]", "PASS - decryptor wiring verified" if ok else "FAIL")
    return 0 if ok else 1


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="JDY tasking decryptor (AES-128-CBC).")
    ap.add_argument("path", nargs="?", help="file with base64 blob, or '-' for stdin")
    ap.add_argument("--b64", dest="b64", help="inline base64 blob")
    ap.add_argument("--iv", choices=["auto", "ascii", "zero"], default="auto",
                    help="IV selection (default: auto = try both, pick JSON-valid)")
    ap.add_argument("--selftest", action="store_true",
                    help="run built-in round-trip test and exit")
    ap.add_argument("--demo", action="store_true",
                    help="create a sample tasking blob and decrypt it (no input file needed)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.demo:
        from Crypto.Util.Padding import pad
        task = {
            "scan_type": "port_scan",
            "task_id": "T-2026-0617",
            "sub_task_id": "S-1",
            "content": "198.51.100.0/24:443,8443; fp=fortinet; CVE-2026-35616",
        }
        ct = AES.new(KEY, AES.MODE_CBC, IV_ASCII).encrypt(
            pad(json.dumps(task).encode(), BLOCK))
        print("[demo] built a sample encrypted tasking blob, now decrypting it...\n")
        pt, label, jok = decrypt_auto(ct)
        emit(pt, label, jok)
        print("\n[demo] This is exactly what you will see with a REAL probe_task blob.")
        sys.exit(0)

    if args.b64 is None and not args.path:
        ap.error("provide a base64 blob: a file path, '-', or --b64")

    try:
        ct = load_b64(args.b64, args.path or "-")
    except ValueError as e:
        print(f"[x] input error: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"[i] ciphertext: {len(ct)} bytes  ({len(ct)//BLOCK} blocks)")
    if len(ct) % BLOCK != 0:
        print(f"[x] not 16-byte aligned - the base64 likely isn't the raw AES "
              f"blob (extra framing? wrong field?).", file=sys.stderr)
        sys.exit(2)

    try:
        if args.iv == "ascii":
            pt = decrypt_once(ct, IV_ASCII); emit(pt, "ascii (0x30 x16)", _looks_like_json(pt))
        elif args.iv == "zero":
            pt = decrypt_once(ct, IV_ZERO); emit(pt, "zero (0x00 x16)", _looks_like_json(pt))
        else:
            pt, label, jok = decrypt_auto(ct); emit(pt, label, jok)
    except ValueError as e:
        print(f"\n[x] DECRYPT FAILED: {e}", file=sys.stderr)
        print("    -> valid padding not produced. This usually means the "
              "ciphertext\n       isn't the raw AES blob (wrong field / extra "
              "framing), not that\n       the scheme is wrong. Re-check what you "
              "fed in.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

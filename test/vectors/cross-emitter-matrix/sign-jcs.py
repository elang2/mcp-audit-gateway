#!/usr/bin/env python3
# Cross-emitter matrix — Python signer (JCS RFC 8785 variant).
# Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
# Uses RFC 8785 JCS canonical form instead of the tuple-array construction.
#
# REQUIRED pip package: `rfc8785` (Trail of Bits, v0.1.4 or newer).
#   Install:  pip install rfc8785
#   Source :  https://github.com/trailofbits/rfc-8785.py
#   PyPI   :  https://pypi.org/project/rfc8785/
# Byte-for-byte compatible with the cyberphone reference vectors.
#
# Signing key: hex-encoded 32-byte Ed25519 secret from SIGNING_KEY_HEX env var.
# Daemon protocol: DAEMON_MODE=1 → newline-delimited id-envelope requests
# {"id":"<opaque>","record":<object>} on stdin; one JSON response per line on
# stdout — {"id":..., "ok":true, "canonical":..., "signature_hex":...} on
# success, {"id":..., "ok":false, "error":"..."} on failure — one response per
# request line, always. Keeps interpreter warm across records.

import json
import os
import re
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Fallback id-extraction regex used only when json.loads on the envelope fails,
# so the caller can still correlate the {"ok":False} rejection to its request.
ID_REGEX = re.compile(r'"id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))')


def sign_one(record, private_key):
    # RFC 8785 JCS: rfc8785.dumps returns bytes already in canonical form
    # (sorted keys, ES6 number formatting, no whitespace, UTF-8 escaping per spec).
    canonical_bytes = rfc8785.dumps(record)
    canonical = canonical_bytes.decode("utf-8")
    sig = private_key.sign(canonical_bytes)
    return {"canonical": canonical, "signature_hex": sig.hex()}


def extract_id_fallback(line):
    m = ID_REGEX.search(line)
    if not m:
        return None
    if m.group(1) is not None:
        try:
            return json.loads('"' + m.group(1) + '"')
        except Exception:
            return m.group(1)
    raw = m.group(2)
    try:
        return float(raw) if "." in raw else int(raw)
    except Exception:
        return raw


def daemon_main(private_key):
    # Env pinning: only set fallbacks; do not override the driver.
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    while True:
        line = sys.stdin.readline()
        if not line:
            break  # EOF — exit loop, terminate daemon
        line = line.strip()
        if not line:
            continue  # skip blank keep-alive lines
        req_id = None
        try:
            try:
                req = json.loads(line)
            except Exception:
                # Salvage the id via regex so the rejection line still correlates.
                req_id = extract_id_fallback(line)
                raise
            req_id = req.get("id")
            record = req["record"]
            body = sign_one(record, private_key)
            resp = {
                "id": req_id,
                "ok": True,
                "canonical": body["canonical"],
                "signature_hex": body["signature_hex"],
            }
        except Exception as e:  # noqa: BLE001 — protocol requires per-record recovery
            resp = {"id": req_id, "ok": False, "error": str(e)}
        try:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception:
            # stdout gone; next readline() will return EOF and terminate the loop.
            break


def main():
    key_hex = os.environ.get("SIGNING_KEY_HEX")
    if not key_hex:
        print("SIGNING_KEY_HEX required", file=sys.stderr)
        sys.exit(1)
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))

    if os.environ.get("DAEMON_MODE") == "1":
        daemon_main(private_key)
        return

    # One-shot mode: byte-identical to pre-patch behavior.
    record = json.loads(sys.stdin.read())
    sys.stdout.write(json.dumps(sign_one(record, private_key)))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Cross-emitter matrix — Python signer.
# Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
# Uses tuple-array canonical form matching ../verify.py.
# Signing key: hex-encoded 32-byte Ed25519 secret from SIGNING_KEY_HEX env var.

import hashlib
import json
import os
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


FIELD_ORDER = [
    "id", "timestamp", "method", "toolName", "namespace", "upstream",
    "principal", "durationMs", "success", "errorCode", "previousHash",
]


def assert_well_formed(value):
    for i, ch in enumerate(value):
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError(f"unpaired surrogate at index {i}")


def canonicalize_value(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        assert_well_formed(value)
        return value
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError(f"unsafe number {value}")
        return value
    if isinstance(value, float):
        raise ValueError(f"unsafe number {value}")
    if isinstance(value, list):
        return ["L", [canonicalize_value(v) for v in value]]
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        for k in keys:
            assert_well_formed(k)
        return ["M", [[k, canonicalize_value(value[k])] for k in keys]]
    raise ValueError(f"unsupported type {type(value)}")


def canonicalize(record):
    ordered = [[k, canonicalize_value(record.get(k))] for k in FIELD_ORDER]
    for optional in ("decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"):
        if record.get(optional) is not None:
            ordered.append([optional, canonicalize_value(record[optional])])
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def daemon_main():
    # Env pinning: only set fallbacks; do not override the driver.
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    key_hex = os.environ.get("SIGNING_KEY_HEX")
    if not key_hex:
        print("SIGNING_KEY_HEX required", file=sys.stderr)
        sys.exit(1)
    # Load the Ed25519 private key exactly once; reuse across every record.
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))

    while True:
        line = sys.stdin.readline()
        if not line:
            break  # EOF — exit loop, terminate daemon
        line = line.strip()
        if not line:
            continue  # skip blank keep-alive lines
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            record = req["record"]
            canonical = canonicalize(record)
            sig = private_key.sign(canonical.encode("utf-8"))
            resp = {
                "id": req_id,
                "ok": True,
                "canonical": canonical,
                "signature_hex": sig.hex(),
            }
        except Exception as e:
            resp = {"id": req_id, "ok": False, "error": str(e)}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


def main():
    if os.environ.get("DAEMON_MODE") == "1":
        daemon_main()
        return

    # One-shot mode: byte-identical to pre-patch behavior.
    key_hex = os.environ.get("SIGNING_KEY_HEX")
    if not key_hex:
        print("SIGNING_KEY_HEX required", file=sys.stderr)
        sys.exit(1)
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))

    record = json.loads(sys.stdin.read())
    canonical = canonicalize(record)
    sig = private_key.sign(canonical.encode("utf-8"))
    print(json.dumps({"canonical": canonical, "signature_hex": sig.hex()}))


if __name__ == "__main__":
    main()

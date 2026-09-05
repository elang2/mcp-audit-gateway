#!/usr/bin/env python3
# Cross-emitter matrix — Python verifier.
# Reads {record, signature_hex, public_key_hex} JSON from stdin.
# Locally recomputes canonical form from record, verifies signature against it.
# Writes {verified: bool, local_canonical, sig_hex} to stdout.

import json
import os
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


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

    # Cache Ed25519PublicKey objects keyed by hex — the whole point of the
    # daemon is to avoid rebuilding crypto state on every record.
    pk_cache = {}

    def _get_pk(pk_hex):
        pk = pk_cache.get(pk_hex)
        if pk is None:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
            pk_cache[pk_hex] = pk
        return pk

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
            sig_hex = req["signature_hex"]
            pk_hex = req["public_key_hex"]
            public_key = _get_pk(pk_hex)

            try:
                local_canonical = canonicalize(record)
                public_key.verify(
                    bytes.fromhex(sig_hex), local_canonical.encode("utf-8")
                )
                verified = True
            except InvalidSignature:
                verified = False
            except Exception as e:
                verified = False
                local_canonical = f"ERROR: {e}"

            resp = {
                "id": req_id,
                "ok": True,
                "verified": verified,
                "local_canonical": local_canonical,
                "sig_hex": sig_hex,
            }
        except Exception as e:
            # Request-level failure (bad JSON, missing field, malformed hex).
            resp = {"id": req_id, "ok": False, "error": str(e)}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


def main():
    if os.environ.get("DAEMON_MODE") == "1":
        daemon_main()
        return

    # One-shot mode: byte-identical to pre-patch behavior.
    payload = json.loads(sys.stdin.read())
    record = payload["record"]
    sig_hex = payload["signature_hex"]
    pk_hex = payload["public_key_hex"]

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))

    try:
        local_canonical = canonicalize(record)
        public_key.verify(bytes.fromhex(sig_hex), local_canonical.encode("utf-8"))
        verified = True
    except InvalidSignature:
        verified = False
    except Exception as e:
        verified = False
        local_canonical = f"ERROR: {e}"

    print(json.dumps({"verified": verified, "local_canonical": local_canonical, "sig_hex": sig_hex}))


if __name__ == "__main__":
    main()

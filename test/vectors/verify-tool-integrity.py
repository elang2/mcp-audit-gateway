#!/usr/bin/env python3
"""
Cross-language conformance verifier for tool-definition canonicalization.
Verifies: SHA-256(JCS(toolDefinition)) matches expected digests.

Requires: pip install rfc8785
(NOT canonicaljson — that's Matrix canonical JSON, rejects floats)
"""
import hashlib
import json
import os
import sys

try:
    import rfc8785
except ImportError:
    print("ERROR: 'rfc8785' package required. Install with: pip install rfc8785")
    print("       Do NOT use 'canonicaljson' — it's Matrix canonical JSON, not RFC 8785.")
    sys.exit(2)


def compute_digest(tool: dict) -> str:
    canonical = rfc8785.dumps(tool)
    return hashlib.sha256(canonical).hexdigest()


def main():
    vectors_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "tool-definition-canonicalization.json",
    )
    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    passed = 0
    failed = 0
    skipped = 0

    print("=== Positive vectors (expected digest must match) ===\n")
    for vec in vectors["positive"]:
        try:
            actual = compute_digest(vec["tool"])
            if actual == vec["expectedDigest"]:
                print(f"  ✓ {vec['id']}: {vec['description']}")
                passed += 1
            else:
                print(f"  ✗ {vec['id']}: {vec['description']}")
                print(f"    expected: {vec['expectedDigest']}")
                print(f"    actual:   {actual}")
                failed += 1
        except Exception as e:
            print(f"  ✗ {vec['id']}: {vec['description']} — ERROR: {e}")
            failed += 1

    print("\n=== Negative vectors ===\n")
    for vec in vectors["negative"]:
        vtype = vec["type"]
        if vtype == "same_digest":
            try:
                d_a = compute_digest(vec["toolA"])
                d_b = compute_digest(vec["toolB"])
                if d_a == d_b:
                    print(f"  ✓ {vec['id']}: {vec['description']}")
                    if "expectedDigest" in vec and d_a != vec["expectedDigest"]:
                        print(f"    WARNING: digests match but differ from expected")
                    passed += 1
                else:
                    print(f"  ✗ {vec['id']}: {vec['description']}")
                    print(f"    digestA: {d_a}")
                    print(f"    digestB: {d_b}")
                    print(f"    Expected same digest but got different")
                    failed += 1
            except Exception as e:
                print(f"  ✗ {vec['id']}: ERROR: {e}")
                failed += 1
        elif vtype == "different_digest":
            try:
                d_a = compute_digest(vec["toolA"])
                d_b = compute_digest(vec["toolB"])
                if d_a != d_b:
                    print(f"  ✓ {vec['id']}: {vec['description']}")
                    if "digestA" in vec and d_a != vec["digestA"]:
                        print(f"    WARNING: digestA mismatch: expected {vec['digestA']}, got {d_a}")
                    if "digestB" in vec and d_b != vec["digestB"]:
                        print(f"    WARNING: digestB mismatch: expected {vec['digestB']}, got {d_b}")
                    passed += 1
                else:
                    print(f"  ✗ {vec['id']}: {vec['description']}")
                    print(f"    Both produced: {d_a}")
                    print(f"    Expected different digests")
                    failed += 1
            except Exception as e:
                print(f"  ✗ {vec['id']}: ERROR: {e}")
                failed += 1
        elif vtype == "must_reject":
            print(f"  ~ {vec['id']}: {vec['description']} (validation-level, skipped in JSON verifier)")
            skipped += 1

    print("\n=== Drift vectors (before/after digest comparison) ===\n")
    for vec in vectors["drift"]:
        try:
            before_d = compute_digest(vec["before"])
            after_d = compute_digest(vec["after"])
            drift_detected = before_d != after_d

            if drift_detected == vec["driftExpected"]:
                print(f"  ✓ {vec['id']}: {vec['description']}")
                if "beforeDigest" in vec and before_d != vec["beforeDigest"]:
                    print(f"    WARNING: beforeDigest mismatch")
                if "afterDigest" in vec and after_d != vec["afterDigest"]:
                    print(f"    WARNING: afterDigest mismatch")
                passed += 1
            else:
                print(f"  ✗ {vec['id']}: {vec['description']}")
                print(f"    before: {before_d}")
                print(f"    after:  {after_d}")
                print(f"    drift detected: {drift_detected}, expected: {vec['driftExpected']}")
                failed += 1
        except Exception as e:
            print(f"  ✗ {vec['id']}: ERROR: {e}")
            failed += 1

    print(f"\n=== Results ===")
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    print(f"  Skipped: {skipped}")
    print(f"  Total:   {passed + failed + skipped}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

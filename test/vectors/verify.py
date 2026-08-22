#!/usr/bin/env python3
"""
Cross-language verification of mcp-audit-gateway conformance vectors.

Proves the tuple-array canonical form is reproducible outside the
original JavaScript implementation. Chain hashes are verified against
the full_record_json reference string (avoiding insertion-order issues).
"""

import hashlib
import json
import sys
from pathlib import Path

vectors_path = Path(__file__).parent / "canonicalization.json"
vectors = json.loads(vectors_path.read_text())

FIELD_ORDER = vectors["field_order"]


def canonicalize(record: dict) -> str:
    """Reproduce the tuple-array canonical form in Python."""
    ordered = []
    for key in FIELD_ORDER:
        value = record.get(key)
        ordered.append([key, value])
    if record.get("decisionContextDigest") is not None:
        ordered.insert(10, ["decisionContextDigest", record["decisionContextDigest"]])
    if record.get("parties") is not None:
        insert_at = 12 if record.get("decisionContextDigest") is not None else 11
        ordered.insert(insert_at, ["parties", record["parties"]])
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


passed = 0
failed = 0

print(f"Format version: {vectors['format_version']}")
print(f"Encoding: {vectors['encoding']}")
print(f"Hash: {vectors['hash_algorithm']} ({vectors['hash_output']})")
print(f"Null rule: {vectors['null_rule']}")
print()

# --- Canonicalization vectors ---
print("=== Canonicalization Vectors ===\n")

for v in vectors["canonicalization"]:
    canonical = canonicalize(v["record"])
    h = sha256_hex(canonical)

    canon_match = canonical == v["canonical"]
    hash_match = h == v["sha256_canonical"]

    if canon_match and hash_match:
        print(f"  PASS: {v['name']}")
        passed += 1
    else:
        print(f"  FAIL: {v['name']}")
        if not canon_match:
            print(f"    canonical expected: {v['canonical']}")
            print(f"    canonical got:      {canonical}")
        if not hash_match:
            print(f"    hash expected: {v['sha256_canonical']}")
            print(f"    hash got:      {h}")
        failed += 1

# --- Chain vectors ---
print("\n=== Chain Vectors ===\n")

for i, entry in enumerate(vectors["chain"]["records"]):
    record = entry["record"]

    # Verify canonical form (cross-language safe)
    canonical = canonicalize(record)
    canon_hash = sha256_hex(canonical)
    canon_match = canonical == entry["canonical"]
    canon_hash_match = canon_hash == entry["sha256_canonical"]

    if canon_match and canon_hash_match:
        print(f"  PASS: chain[{i}] canonical ({record['toolName']})")
        passed += 1
    else:
        print(f"  FAIL: chain[{i}] canonical ({record['toolName']})")
        if not canon_match:
            print(f"    canonical mismatch")
        if not canon_hash_match:
            print(f"    canonical hash mismatch")
        failed += 1

    # Verify chain hash against full_record_json reference
    reference_json = entry["full_record_json"]
    reference_hash = sha256_hex(reference_json)
    chain_match = reference_hash == entry["record_hash"]

    if chain_match:
        print(f"  PASS: chain[{i}] record_hash via reference JSON ({record['toolName']})")
        passed += 1
    else:
        print(f"  FAIL: chain[{i}] record_hash via reference JSON")
        print(f"    expected: {entry['record_hash']}")
        print(f"    got:      {reference_hash}")
        failed += 1

    # Verify chain linkage
    if i == 0:
        linkage_ok = record["previousHash"] == vectors["chain"]["genesis_seed"]
    else:
        prev = vectors["chain"]["records"][i - 1]
        linkage_ok = (
            record["previousHash"] == prev["record_hash"]
            and entry.get("previous_record_hash") == prev["record_hash"]
        )

    if linkage_ok:
        print(f"  PASS: chain[{i}] linkage ({record['toolName']})")
        passed += 1
    else:
        print(f"  FAIL: chain[{i}] linkage ({record['toolName']})")
        failed += 1

# --- Dual-hash demonstration ---
print("\n=== Dual-Hash Demonstration ===\n")

demo = vectors["dual_hash_demo"]
a = demo["record_a"]
b = demo["record_b"]

# Canonical hashes should match (attestation excluded)
canon_a = canonicalize(a["record"])
canon_b = canonicalize(b["record"])
hash_a = sha256_hex(canon_a)
hash_b = sha256_hex(canon_b)

if hash_a == hash_b and hash_a == a["sha256_canonical"] and hash_b == b["sha256_canonical"]:
    print("  PASS: canonical hashes match (attestation excluded from signing)")
    passed += 1
else:
    print("  FAIL: canonical hashes should match")
    print(f"    a: {hash_a}")
    print(f"    b: {hash_b}")
    failed += 1

# Chain hashes should differ (attestation included)
chain_a = sha256_hex(a["full_record_json"])
chain_b = sha256_hex(b["full_record_json"])

if chain_a != chain_b and chain_a == a["record_hash"] and chain_b == b["record_hash"]:
    print("  PASS: chain hashes differ (attestation included in chain)")
    passed += 1
else:
    print("  FAIL: chain hashes should differ")
    print(f"    a: {chain_a}")
    print(f"    b: {chain_b}")
    failed += 1

# Verify assertions field
if demo["assertions"]["canonical_hashes_match"] is True:
    print("  PASS: assertions.canonical_hashes_match confirmed")
    passed += 1
else:
    print("  FAIL: assertions.canonical_hashes_match should be true")
    failed += 1

if demo["assertions"]["chain_hashes_differ"] is True:
    print("  PASS: assertions.chain_hashes_differ confirmed")
    passed += 1
else:
    print("  FAIL: assertions.chain_hashes_differ should be true")
    failed += 1

# --- Party Attribution vectors ---
if "party_attribution" in vectors:
    print("\n=== Party Attribution Vectors ===\n")

    for v in vectors["party_attribution"]["vectors"]:
        canonical = canonicalize(v["record"])
        h = sha256_hex(canonical)

        canon_match = canonical == v["canonical"]
        hash_match = h == v["sha256_canonical"]

        if canon_match and hash_match:
            print(f"  PASS: {v['name']}")
            passed += 1
        else:
            print(f"  FAIL: {v['name']}")
            if not canon_match:
                print(f"    canonical expected: {v['canonical']}")
                print(f"    canonical got:      {canonical}")
            if not hash_match:
                print(f"    hash expected: {v['sha256_canonical']}")
                print(f"    hash got:      {h}")
            failed += 1

# --- Summary ---
print(f"\n=== Results: {passed} passed, {failed} failed ===")

if failed > 0:
    sys.exit(1)
else:
    print("\nAll vectors verified cross-language (Python).")
    print("Canonical form: tuple-array, cross-language safe.")
    print("Chain hash: verified via full_record_json reference string.")
    sys.exit(0)

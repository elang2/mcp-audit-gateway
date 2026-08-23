#!/usr/bin/env python3
"""
Checkpoint conformance vector verifier (Python).
Verifies that checkpoint canonicalization, chain hashing, and truncation
detection produce byte-identical results across implementations.
"""

import hashlib
import json
import sys
from pathlib import Path

vectors_path = Path(__file__).parent / "checkpoint.json"
vectors = json.loads(vectors_path.read_text())

passed = 0
failed = 0


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def assert_well_formed_string(value: str, context: str) -> None:
    for i, ch in enumerate(value):
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError(f"{context}: unpaired surrogate at index {i}")


def canonicalize_checkpoint(record: dict) -> str:
    assert_well_formed_string(record["id"], "canonicalizeCheckpoint.id")
    assert_well_formed_string(record["timestamp"], "canonicalizeCheckpoint.timestamp")
    assert_well_formed_string(record["previousHash"], "canonicalizeCheckpoint.previousHash")
    ordered = [
        ["id", record["id"]],
        ["type", "checkpoint"],
        ["timestamp", record["timestamp"]],
        ["sequence", record["sequence"]],
        ["recordCount", record["recordCount"]],
        ["previousHash", record["previousHash"]],
    ]
    if record.get("parties") is not None:
        ordered.append(["parties", record["parties"]])
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def hash_record(record: dict) -> str:
    serialized = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def check(condition: bool, name: str, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")
        if detail:
            print(f"        {detail}")


# --- Checkpoint Canonicalization ---
print("\n=== Checkpoint Canonicalization ===")
for vec in vectors["checkpoint_canonicalization"]:
    canonical = canonicalize_checkpoint(vec["record"])
    check(
        canonical == vec["canonical"],
        f"{vec['name']} canonical form",
        f"expected: {vec['canonical']}\n        got:      {canonical}",
    )
    h = sha256(canonical)
    check(
        h == vec["sha256_canonical"],
        f"{vec['name']} SHA-256",
        f"expected: {vec['sha256_canonical']}\n        got:      {h}",
    )

# --- Checkpoint Chain ---
print("\n=== Checkpoint Chain ===")
chain_records = vectors["checkpoint_chain"]["records"]
for i, entry in enumerate(chain_records):
    computed = hash_record(entry["record"])
    check(
        computed == entry["record_hash"],
        f"chain record {i} hash",
        f"expected: {entry['record_hash']}\n        got:      {computed}",
    )
    if i > 0:
        check(
            entry["record"]["previousHash"] == chain_records[i - 1]["record_hash"],
            f"chain record {i} previousHash links to record {i - 1}",
            f"expected: {chain_records[i - 1]['record_hash']}\n        got:      {entry['record']['previousHash']}",
        )

# --- Truncation Detection ---
print("\n=== Truncation Detection ===")
trunc_vec = vectors["truncation_detection"]
ext_ckpt = trunc_vec["external_checkpoint"]

# Full chain should contain the checkpoint
full_chain = [e["record"] for e in chain_records]
found_in_full = any(
    r.get("type") == "checkpoint"
    and r.get("previousHash") == ext_ckpt["previousHash"]
    and r.get("sequence") == ext_ckpt["sequence"]
    and r.get("recordCount") == ext_ckpt["recordCount"]
    for r in full_chain
)
check(found_in_full, "full chain contains externalized checkpoint")

# Truncated chain should NOT contain the checkpoint
truncated_chain = trunc_vec["truncated_chain"]["records_delivered"]
found_in_truncated = any(
    r.get("type") == "checkpoint"
    and r.get("previousHash") == ext_ckpt["previousHash"]
    and r.get("sequence") == ext_ckpt["sequence"]
    and r.get("recordCount") == ext_ckpt["recordCount"]
    for r in truncated_chain
)
has_descendant = any(
    r.get("type") == "checkpoint" and r.get("sequence", 0) > ext_ckpt["sequence"]
    for r in truncated_chain
)
check(
    not found_in_truncated and not has_descendant,
    "truncated chain missing checkpoint (truncation detected)",
)

# --- canonicalizeValue ---
print("\n=== canonicalizeValue ===")


def canonicalize_value(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError(f"unsafe number {value}")
        return value
    if isinstance(value, float):
        raise ValueError(f"unsafe number {value}")
    if isinstance(value, str):
        for i, ch in enumerate(value):
            code = ord(ch)
            if 0xD800 <= code <= 0xDFFF:
                raise ValueError(f"unpaired surrogate at index {i}")
        return value
    if isinstance(value, list):
        return ["L", [canonicalize_value(v) for v in value]]
    if isinstance(value, dict):
        # Sort by UTF-16 code-unit order to match JavaScript's String.prototype.sort().
        # Python sorts by code points; these diverge for astral-plane characters.
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        return ["M", [[k, canonicalize_value(value[k])] for k in keys]]
    raise ValueError(f"unsupported type {type(value)}")


def compute_extensions_digest(extensions: dict) -> tuple:
    canonicalized = canonicalize_value(extensions)
    canonical = json.dumps(canonicalized, separators=(",", ":"), ensure_ascii=False)
    return canonical, sha256(canonical)


cv_vectors = vectors["canonicalize_value"]["vectors"]
for vec in cv_vectors:
    if "expected_error" in vec:
        threw = False
        if "construct" in vec:
            # Programmatic: lone surrogate can't reliably live in JSON
            try:
                canonicalize_value(chr(0xD800))
            except (ValueError, UnicodeEncodeError):
                threw = True
        else:
            try:
                canonicalize_value(vec["input"])
            except ValueError:
                threw = True
        check(threw, f"{vec['name']} throws on invalid input")
        continue
    if "input_a" in vec and "input_b" in vec and "canonical_form" in vec:
        ra_c, ra_d = compute_extensions_digest(vec["input_a"])
        rb_c, rb_d = compute_extensions_digest(vec["input_b"])
        check(ra_c == vec["canonical_form"], f"{vec['name']} canonical form",
              f"expected: {vec['canonical_form']}\n        got:      {ra_c}")
        check(ra_d == vec["digest"], f"{vec['name']} digest",
              f"expected: {vec['digest']}\n        got:      {ra_d}")
        check(ra_d == rb_d, f"{vec['name']} both inputs produce same digest")
    elif "input_a" in vec and "canonical_a" in vec:
        ra_c, ra_d = compute_extensions_digest(vec["input_a"])
        rb_c, rb_d = compute_extensions_digest(vec["input_b"])
        check(ra_c == vec["canonical_a"], f"{vec['name']} canonical_a")
        check(ra_d == vec["digest_a"], f"{vec['name']} digest_a")
        check(rb_c == vec["canonical_b"], f"{vec['name']} canonical_b")
        check(rb_d == vec["digest_b"], f"{vec['name']} digest_b")
        check(ra_d != rb_d, f"{vec['name']} digests differ")
    elif "input" in vec:
        r_c, r_d = compute_extensions_digest(vec["input"])
        check(r_c == vec["canonical_form"], f"{vec['name']} canonical form",
              f"expected: {vec['canonical_form']}\n        got:      {r_c}")
        check(r_d == vec["digest"], f"{vec['name']} digest",
              f"expected: {vec['digest']}\n        got:      {r_d}")

# --- Extensions Digest ---
print("\n=== Extensions Digest ===")
ext_vectors = vectors["extensions_digest"]["vectors"]

for vec in ext_vectors:
    canonical, digest = compute_extensions_digest(vec["extensions"])
    check(
        canonical == vec["canonical_form"],
        f"{vec['name']} canonical form",
        f"expected: {vec['canonical_form']}\n        got:      {canonical}",
    )
    check(
        digest == vec["digest"],
        f"{vec['name']} digest",
        f"expected: {vec['digest']}\n        got:      {digest}",
    )


def canonicalize_record(record: dict) -> str:
    assert_well_formed_string(record["id"], "canonicalizeRecord.id")
    assert_well_formed_string(record["timestamp"], "canonicalizeRecord.timestamp")
    assert_well_formed_string(record["method"], "canonicalizeRecord.method")
    if record.get("toolName") is not None:
        assert_well_formed_string(record["toolName"], "canonicalizeRecord.toolName")
    if record.get("namespace") is not None:
        assert_well_formed_string(record["namespace"], "canonicalizeRecord.namespace")
    if record.get("upstream") is not None:
        assert_well_formed_string(record["upstream"], "canonicalizeRecord.upstream")
    if record.get("principal") is not None:
        assert_well_formed_string(record["principal"], "canonicalizeRecord.principal")
    if record.get("previousHash") is not None:
        assert_well_formed_string(record["previousHash"], "canonicalizeRecord.previousHash")
    if record.get("decisionContextDigest") is not None:
        assert_well_formed_string(record["decisionContextDigest"], "canonicalizeRecord.decisionContextDigest")
    if record.get("extensionsDigest") is not None:
        assert_well_formed_string(record["extensionsDigest"], "canonicalizeRecord.extensionsDigest")
    ordered = [
        ["id", record["id"]],
        ["timestamp", record["timestamp"]],
        ["method", record["method"]],
        ["toolName", record.get("toolName")],
        ["namespace", record.get("namespace")],
        ["upstream", record.get("upstream")],
        ["principal", record.get("principal")],
        ["durationMs", record["durationMs"]],
        ["success", record["success"]],
        ["errorCode", record.get("errorCode")],
        ["previousHash", record.get("previousHash")],
    ]
    insert_at = 11
    if record.get("decisionContextDigest") is not None:
        ordered.insert(10, ["decisionContextDigest", record["decisionContextDigest"]])
        insert_at = 12
    if record.get("extensionsDigest") is not None:
        ordered.insert(insert_at, ["extensionsDigest", record["extensionsDigest"]])
        insert_at += 1
    if record.get("aiInvocation") is not None:
        ordered.insert(insert_at, ["aiInvocation", canonicalize_value(record["aiInvocation"])])
        insert_at += 1
    if record.get("parties") is not None:
        ordered.insert(insert_at, ["parties", record["parties"]])
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


rec_canon = vectors["extensions_digest"]["record_canonicalization"]

with_ext = rec_canon["with_extensions_digest"]
with_ext_canonical = canonicalize_record(with_ext["record"])
check(
    with_ext_canonical == with_ext["canonical"],
    "record with extensionsDigest canonical form",
    f"expected: {with_ext['canonical']}\n        got:      {with_ext_canonical}",
)
check(
    sha256(with_ext_canonical) == with_ext["sha256_canonical"],
    "record with extensionsDigest SHA-256",
    f"expected: {with_ext['sha256_canonical']}\n        got:      {sha256(with_ext_canonical)}",
)

without_ext = rec_canon["without_extensions_digest"]
without_ext_canonical = canonicalize_record(without_ext["record"])
check(
    without_ext_canonical == without_ext["canonical"],
    "record without extensionsDigest canonical form (backward compat)",
    f"expected: {without_ext['canonical']}\n        got:      {without_ext_canonical}",
)
check(
    sha256(without_ext_canonical) == without_ext["sha256_canonical"],
    "record without extensionsDigest SHA-256",
    f"expected: {without_ext['sha256_canonical']}\n        got:      {sha256(without_ext_canonical)}",
)

# --- Rotation Boundary ---
print("\n=== Rotation Boundary ===")
rotation = vectors["rotation_boundary"]

for i, entry in enumerate(rotation["file_1_records"]):
    h = hash_record(entry["record"])
    check(
        h == entry["record_hash"],
        f"rotation file1 record {i} hash",
        f"expected: {entry['record_hash']}\n        got:      {h}",
    )

file1_last_hash = rotation["file_1_records"][-1]["record_hash"]
file2_first = rotation["file_2_records"][0]
check(
    file2_first["record"]["previousHash"] == file1_last_hash,
    "rotation: file2 first record chains to file1 last hash",
    f"expected: {file1_last_hash}\n        got:      {file2_first['record']['previousHash']}",
)
file2_hash = hash_record(file2_first["record"])
check(
    file2_hash == file2_first["record_hash"],
    "rotation file2 record 0 hash",
    f"expected: {file2_first['record_hash']}\n        got:      {file2_hash}",
)

# --- Sequence Regression ---
print("\n=== Sequence Regression ===")
seq_reg = vectors["sequence_regression"]
checkpoints = [e for e in seq_reg["chain"] if e["record"].get("type") == "checkpoint"]
regression_detected = False
for i in range(1, len(checkpoints)):
    if checkpoints[i]["record"]["sequence"] <= checkpoints[i - 1]["record"]["sequence"]:
        regression_detected = True
check(regression_detected, "sequence regression detected in chain")
check(
    seq_reg["detection_result"]["failureCode"] == "sequence_regression",
    "failure code is sequence_regression",
)

# --- Chain Break ---
print("\n=== Chain Break ===")
chain_break = vectors["chain_break"]
for i, entry in enumerate(chain_break["records"]):
    h = hash_record(entry["record"])
    check(
        h == entry["record_hash"],
        f"chain_break record {i} hash",
        f"expected: {entry['record_hash']}\n        got:      {h}",
    )
check(
    chain_break["records"][1]["record"]["previousHash"] == chain_break["records"][0]["record_hash"],
    "record after chain_break chains from break record hash",
)

# --- Summary ---
print(f"\n=== Results: {passed} passed, {failed} failed ({passed + failed} total) ===")
sys.exit(1 if failed > 0 else 0)

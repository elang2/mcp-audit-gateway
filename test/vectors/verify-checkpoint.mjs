#!/usr/bin/env node
/**
 * Checkpoint conformance vector verifier (JavaScript).
 * Verifies that checkpoint canonicalization, chain hashing, and truncation
 * detection produce byte-identical results across implementations.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(await readFile(join(__dirname, "checkpoint.json"), "utf-8"));

let passed = 0;
let failed = 0;

function sha256(input) {
  return createHash("sha256").update(input).digest("hex");
}

function canonicalizeCheckpoint(record) {
  const ordered = [
    ["id", record.id],
    ["type", "checkpoint"],
    ["timestamp", record.timestamp],
    ["sequence", record.sequence],
    ["recordCount", record.recordCount],
    ["previousHash", record.previousHash],
  ];
  if (record.parties != null) {
    ordered.push(["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

function hashRecord(record) {
  return createHash("sha256").update(JSON.stringify(record)).digest("hex");
}

function assert(condition, name, detail) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${name}`);
  } else {
    failed++;
    console.log(`  FAIL: ${name}`);
    if (detail) console.log(`        ${detail}`);
  }
}

// --- Checkpoint Canonicalization ---
console.log("\n=== Checkpoint Canonicalization ===");
for (const vec of vectors.checkpoint_canonicalization) {
  const canonical = canonicalizeCheckpoint(vec.record);
  assert(
    canonical === vec.canonical,
    `${vec.name} canonical form`,
    `expected: ${vec.canonical}\n        got:      ${canonical}`
  );
  const hash = sha256(canonical);
  assert(
    hash === vec.sha256_canonical,
    `${vec.name} SHA-256`,
    `expected: ${vec.sha256_canonical}\n        got:      ${hash}`
  );
}

// --- Checkpoint Chain ---
console.log("\n=== Checkpoint Chain ===");
const chainRecords = vectors.checkpoint_chain.records;
for (let i = 0; i < chainRecords.length; i++) {
  const entry = chainRecords[i];
  const computedHash = hashRecord(entry.record);
  assert(
    computedHash === entry.record_hash,
    `chain record ${i} hash`,
    `expected: ${entry.record_hash}\n        got:      ${computedHash}`
  );

  if (i > 0) {
    assert(
      entry.record.previousHash === chainRecords[i - 1].record_hash,
      `chain record ${i} previousHash links to record ${i - 1}`,
      `expected: ${chainRecords[i - 1].record_hash}\n        got:      ${entry.record.previousHash}`
    );
  }
}

// --- Truncation Detection ---
console.log("\n=== Truncation Detection ===");
const truncVec = vectors.truncation_detection;
const extCkpt = truncVec.external_checkpoint;

// Full chain should contain the checkpoint
const fullChain = chainRecords.map(e => e.record);
let foundInFull = false;
for (const rec of fullChain) {
  if (rec.type === "checkpoint" &&
      rec.previousHash === extCkpt.previousHash &&
      rec.sequence === extCkpt.sequence &&
      rec.recordCount === extCkpt.recordCount) {
    foundInFull = true;
  }
}
assert(foundInFull, "full chain contains externalized checkpoint");

// Truncated chain should NOT contain the checkpoint
const truncatedChain = truncVec.truncated_chain.records_delivered;
let foundInTruncated = false;
let hasDescendant = false;
for (const rec of truncatedChain) {
  if (rec.type === "checkpoint") {
    if (rec.previousHash === extCkpt.previousHash &&
        rec.sequence === extCkpt.sequence &&
        rec.recordCount === extCkpt.recordCount) {
      foundInTruncated = true;
    }
    if (rec.sequence > extCkpt.sequence) {
      hasDescendant = true;
    }
  }
}
assert(!foundInTruncated && !hasDescendant, "truncated chain missing checkpoint (truncation detected)");

// --- canonicalizeValue ---
console.log("\n=== canonicalizeValue ===");

function canonicalizeValue(value) {
  if (value === null || value === undefined) return null;
  switch (typeof value) {
    case "string":
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
          const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
          if (next < 0xDC00 || next > 0xDFFF)
            throw new Error(`unpaired surrogate at index ${i}`);
          i++;
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
          throw new Error(`unpaired surrogate at index ${i}`);
        }
      }
      return value;
    case "boolean":
      return value;
    case "number":
      if (!Number.isSafeInteger(value))
        throw new Error(`unsafe number ${value}`);
      return value;
    case "object":
      if (Array.isArray(value)) return ["L", value.map(canonicalizeValue)];
      const keys = Object.keys(value).sort().filter(k => value[k] !== undefined);
      return ["M", keys.map(k => [k, canonicalizeValue(value[k])])];
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

function computeExtensionsDigest(extensions) {
  const canonicalized = canonicalizeValue(extensions);
  const canonical = JSON.stringify(canonicalized);
  return { canonical, digest: sha256(canonical) };
}

const cvVectors = vectors.canonicalize_value.vectors;
for (const vec of cvVectors) {
  if (vec.expected_error) {
    if (vec.construct) {
      // Programmatic construction (e.g. lone surrogate can't be in JSON)
      let threw = false;
      try { canonicalizeValue(String.fromCharCode(0xD800)); } catch { threw = true; }
      assert(threw, `${vec.name} throws on invalid input`);
    } else {
      let threw = false;
      try { canonicalizeValue(vec.input); } catch { threw = true; }
      assert(threw, `${vec.name} throws on invalid input`);
    }
    continue;
  }
  if (vec.input_a && vec.input_b && vec.canonical_form) {
    // Same content different order -> same digest
    const ra = computeExtensionsDigest(vec.input_a);
    const rb = computeExtensionsDigest(vec.input_b);
    assert(ra.canonical === vec.canonical_form, `${vec.name} canonical form`,
      `expected: ${vec.canonical_form}\n        got:      ${ra.canonical}`);
    assert(ra.digest === vec.digest, `${vec.name} digest`, `expected: ${vec.digest}\n        got:      ${ra.digest}`);
    assert(ra.digest === rb.digest, `${vec.name} both inputs produce same digest`);
  } else if (vec.input_a && vec.input_b && vec.canonical_a) {
    // Array order matters
    const ra = computeExtensionsDigest(vec.input_a);
    const rb = computeExtensionsDigest(vec.input_b);
    assert(ra.canonical === vec.canonical_a, `${vec.name} canonical_a`);
    assert(ra.digest === vec.digest_a, `${vec.name} digest_a`);
    assert(rb.canonical === vec.canonical_b, `${vec.name} canonical_b`);
    assert(rb.digest === vec.digest_b, `${vec.name} digest_b`);
    assert(ra.digest !== rb.digest, `${vec.name} digests differ`);
  } else if (vec.input) {
    // Unicode keys
    const r = computeExtensionsDigest(vec.input);
    assert(r.canonical === vec.canonical_form, `${vec.name} canonical form`,
      `expected: ${vec.canonical_form}\n        got:      ${r.canonical}`);
    assert(r.digest === vec.digest, `${vec.name} digest`,
      `expected: ${vec.digest}\n        got:      ${r.digest}`);
  }
}

// --- Extensions Digest ---
console.log("\n=== Extensions Digest ===");
const extVectors = vectors.extensions_digest.vectors;

for (const vec of extVectors) {
  const { canonical, digest } = computeExtensionsDigest(vec.extensions);
  assert(
    canonical === vec.canonical_form,
    `${vec.name} canonical form`,
    `expected: ${vec.canonical_form}\n        got:      ${canonical}`
  );
  assert(
    digest === vec.digest,
    `${vec.name} digest`,
    `expected: ${vec.digest}\n        got:      ${digest}`
  );
}

// Record canonicalization with extensionsDigest
function canonicalizeRecord(record) {
  const ordered = [
    ["id", record.id],
    ["timestamp", record.timestamp],
    ["method", record.method],
    ["toolName", record.toolName ?? null],
    ["namespace", record.namespace ?? null],
    ["upstream", record.upstream ?? null],
    ["principal", record.principal ?? null],
    ["durationMs", record.durationMs],
    ["success", record.success],
    ["errorCode", record.errorCode ?? null],
    ["previousHash", record.previousHash ?? null],
  ];
  let insertAt = 11;
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
    insertAt = 12;
  }
  if (record.extensionsDigest != null) {
    ordered.splice(insertAt, 0, ["extensionsDigest", record.extensionsDigest]);
    insertAt++;
  }
  if (record.parties != null) {
    ordered.splice(insertAt, 0, ["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

const withExt = vectors.extensions_digest.record_canonicalization.with_extensions_digest;
const withExtCanonical = canonicalizeRecord(withExt.record);
assert(
  withExtCanonical === withExt.canonical,
  "record with extensionsDigest canonical form",
  `expected: ${withExt.canonical}\n        got:      ${withExtCanonical}`
);
assert(
  sha256(withExtCanonical) === withExt.sha256_canonical,
  "record with extensionsDigest SHA-256",
  `expected: ${withExt.sha256_canonical}\n        got:      ${sha256(withExtCanonical)}`
);

const withoutExt = vectors.extensions_digest.record_canonicalization.without_extensions_digest;
const withoutExtCanonical = canonicalizeRecord(withoutExt.record);
assert(
  withoutExtCanonical === withoutExt.canonical,
  "record without extensionsDigest canonical form (backward compat)",
  `expected: ${withoutExt.canonical}\n        got:      ${withoutExtCanonical}`
);
assert(
  sha256(withoutExtCanonical) === withoutExt.sha256_canonical,
  "record without extensionsDigest SHA-256",
  `expected: ${withoutExt.sha256_canonical}\n        got:      ${sha256(withoutExtCanonical)}`
);

// --- Rotation Boundary ---
console.log("\n=== Rotation Boundary ===");
const rotation = vectors.rotation_boundary;

// Verify file 1 hashes
for (let i = 0; i < rotation.file_1_records.length; i++) {
  const entry = rotation.file_1_records[i];
  const h = hashRecord(entry.record);
  assert(h === entry.record_hash, `rotation file1 record ${i} hash`,
    `expected: ${entry.record_hash}\n        got:      ${h}`);
}

// Verify file 2 chains to file 1's last record
const file1LastHash = rotation.file_1_records[rotation.file_1_records.length - 1].record_hash;
const file2First = rotation.file_2_records[0];
assert(
  file2First.record.previousHash === file1LastHash,
  "rotation: file2 first record chains to file1 last hash",
  `expected: ${file1LastHash}\n        got:      ${file2First.record.previousHash}`
);
const file2Hash = hashRecord(file2First.record);
assert(file2Hash === file2First.record_hash, "rotation file2 record 0 hash",
  `expected: ${file2First.record_hash}\n        got:      ${file2Hash}`);

// --- Sequence Regression ---
console.log("\n=== Sequence Regression ===");
const seqReg = vectors.sequence_regression;
const checkpoints = seqReg.chain.filter(e => e.record.type === "checkpoint");
let regressionDetected = false;
for (let i = 1; i < checkpoints.length; i++) {
  if (checkpoints[i].record.sequence <= checkpoints[i - 1].record.sequence) {
    regressionDetected = true;
  }
}
assert(regressionDetected, "sequence regression detected in chain");
assert(
  seqReg.detection_result.failureCode === "sequence_regression",
  "failure code is sequence_regression"
);

// --- Chain Break ---
console.log("\n=== Chain Break ===");
const chainBreak = vectors.chain_break;
for (let i = 0; i < chainBreak.records.length; i++) {
  const entry = chainBreak.records[i];
  const h = hashRecord(entry.record);
  assert(h === entry.record_hash, `chain_break record ${i} hash`,
    `expected: ${entry.record_hash}\n        got:      ${h}`);
}
// Verify chaining: second record's previousHash = first record's hash
assert(
  chainBreak.records[1].record.previousHash === chainBreak.records[0].record_hash,
  "record after chain_break chains from break record hash"
);

// --- Summary ---
console.log(`\n=== Results: ${passed} passed, ${failed} failed (${passed + failed} total) ===`);
process.exit(failed > 0 ? 1 : 0);

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(__dirname, "canonicalization.json"), "utf-8"),
);

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

function canonicalizeFromRecord(record, fieldOrder) {
  const ordered = fieldOrder.map((key) => [key, record[key] ?? null]);
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
  }
  if (record.parties != null) {
    const insertAt = record.decisionContextDigest != null ? 12 : 11;
    ordered.splice(insertAt, 0, ["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

let passed = 0;
let failed = 0;

console.log(`Format version: ${vectors.format_version}`);
console.log(`Encoding: ${vectors.encoding}`);
console.log(`Hash: ${vectors.hash_algorithm} (${vectors.hash_output})`);
console.log();

// --- Canonicalization vectors ---
console.log("=== Canonicalization Vectors ===\n");

for (const v of vectors.canonicalization) {
  const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
  const hash = sha256Hex(canonical);

  const canonMatch = canonical === v.canonical;
  const hashMatch = hash === v.sha256_canonical;

  if (canonMatch && hashMatch) {
    console.log(`  PASS: ${v.name}`);
    passed++;
  } else {
    console.log(`  FAIL: ${v.name}`);
    if (!canonMatch) {
      console.log(`    canonical expected: ${v.canonical}`);
      console.log(`    canonical got:      ${canonical}`);
    }
    if (!hashMatch) {
      console.log(`    hash expected: ${v.sha256_canonical}`);
      console.log(`    hash got:      ${hash}`);
    }
    failed++;
  }
}

// --- Chain vectors ---
console.log("\n=== Chain Vectors ===\n");

for (let i = 0; i < vectors.chain.records.length; i++) {
  const entry = vectors.chain.records[i];
  const record = entry.record;

  // Verify canonical form
  const canonical = canonicalizeFromRecord(record, vectors.field_order);
  const canonHash = sha256Hex(canonical);
  const canonMatch = canonical === entry.canonical;
  const canonHashMatch = canonHash === entry.sha256_canonical;

  if (canonMatch && canonHashMatch) {
    console.log(`  PASS: chain[${i}] canonical (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: chain[${i}] canonical (${record.toolName})`);
    if (!canonMatch) console.log(`    canonical mismatch`);
    if (!canonHashMatch) console.log(`    canonical hash mismatch`);
    failed++;
  }

  // Verify chain hash via full_record_json
  const refHash = sha256Hex(entry.full_record_json);
  if (refHash === entry.record_hash) {
    console.log(`  PASS: chain[${i}] record_hash (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: chain[${i}] record_hash (${record.toolName})`);
    console.log(`    expected: ${entry.record_hash}`);
    console.log(`    got:      ${refHash}`);
    failed++;
  }

  // Verify native JSON.stringify produces same hash
  const nativeJson = JSON.stringify(record);
  const nativeHash = sha256Hex(nativeJson);
  if (nativeHash === entry.record_hash) {
    console.log(`  PASS: chain[${i}] native stringify match (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: chain[${i}] native stringify diverges (${record.toolName})`);
    console.log(`    reference: ${entry.full_record_json}`);
    console.log(`    native:    ${nativeJson}`);
    failed++;
  }

  // Verify linkage
  let linkageOk;
  if (i === 0) {
    linkageOk = record.previousHash === vectors.chain.genesis_seed;
  } else {
    const prev = vectors.chain.records[i - 1];
    linkageOk =
      record.previousHash === prev.record_hash &&
      entry.previous_record_hash === prev.record_hash;
  }

  if (linkageOk) {
    console.log(`  PASS: chain[${i}] linkage (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: chain[${i}] linkage (${record.toolName})`);
    failed++;
  }
}

// --- Dual-hash demonstration ---
console.log("\n=== Dual-Hash Demonstration ===\n");

const demo = vectors.dual_hash_demo;

const canonA = canonicalizeFromRecord(demo.record_a.record, vectors.field_order);
const canonB = canonicalizeFromRecord(demo.record_b.record, vectors.field_order);
const hashA = sha256Hex(canonA);
const hashB = sha256Hex(canonB);

if (hashA === hashB && hashA === demo.record_a.sha256_canonical) {
  console.log("  PASS: canonical hashes match (attestation excluded)");
  passed++;
} else {
  console.log("  FAIL: canonical hashes should match");
  failed++;
}

const chainA = sha256Hex(demo.record_a.full_record_json);
const chainB = sha256Hex(demo.record_b.full_record_json);

if (chainA !== chainB && chainA === demo.record_a.record_hash && chainB === demo.record_b.record_hash) {
  console.log("  PASS: chain hashes differ (attestation included)");
  passed++;
} else {
  console.log("  FAIL: chain hashes should differ");
  failed++;
}

if (demo.assertions.canonical_hashes_match === true) {
  console.log("  PASS: assertions.canonical_hashes_match");
  passed++;
} else {
  console.log("  FAIL: assertions.canonical_hashes_match should be true");
  failed++;
}

if (demo.assertions.chain_hashes_differ === true) {
  console.log("  PASS: assertions.chain_hashes_differ");
  passed++;
} else {
  console.log("  FAIL: assertions.chain_hashes_differ should be true");
  failed++;
}

// --- Party Attribution vectors ---
if (vectors.party_attribution) {
  console.log("\n=== Party Attribution Vectors ===\n");

  for (const v of vectors.party_attribution.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    const hash = sha256Hex(canonical);

    const canonMatch = canonical === v.canonical;
    const hashMatch = hash === v.sha256_canonical;

    if (canonMatch && hashMatch) {
      console.log(`  PASS: ${v.name}`);
      passed++;
    } else {
      console.log(`  FAIL: ${v.name}`);
      if (!canonMatch) {
        console.log(`    canonical expected: ${v.canonical}`);
        console.log(`    canonical got:      ${canonical}`);
      }
      if (!hashMatch) {
        console.log(`    hash expected: ${v.sha256_canonical}`);
        console.log(`    hash got:      ${hash}`);
      }
      failed++;
    }
  }
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);

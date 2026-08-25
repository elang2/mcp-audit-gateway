/**
 * Cross-language verification of mcp-audit-gateway conformance vectors.
 *
 * Chain continuity: hash stored line octets (octets-first, no re-serialization).
 * Canonical form: recompute from parsed record (generate/verify split).
 * Producer conformance: verify JS native stringify reproduces stored octets.
 */

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
      if (!Number.isSafeInteger(value)) throw new Error(`unsafe number ${value}`);
      return value;
    case "object": {
      if (Array.isArray(value)) return ["L", value.map(canonicalizeValue)];
      const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
      return ["M", keys.map((k) => [k, canonicalizeValue(value[k])])];
    }
    default:
      throw new Error(`unsupported type ${typeof value}`);
  }
}

function canonicalizeFromRecord(record, fieldOrder) {
  const ordered = fieldOrder.map((key) => [key, record[key] ?? null]);
  let insertAt = 11;
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
    insertAt = 12;
  }
  if (record.extensionsDigest != null) {
    ordered.splice(insertAt, 0, ["extensionsDigest", record.extensionsDigest]);
    insertAt++;
  }
  if (record.aiInvocation != null) {
    ordered.splice(insertAt, 0, ["aiInvocation", canonicalizeValue(record.aiInvocation)]);
    insertAt++;
  }
  if (record.parties != null) {
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

  // Verify chain continuity via stored line octets (octets-first)
  const storedOctets = entry.full_record_json;
  const chainHash = sha256Hex(storedOctets);
  if (chainHash === entry.record_hash) {
    console.log(`  PASS: chain[${i}] continuity via stored octets (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: chain[${i}] continuity (octets mismatch) (${record.toolName})`);
    console.log(`    expected: ${entry.record_hash}`);
    console.log(`    got:      ${chainHash}`);
    failed++;
  }

  // Producer conformance: verify JS native stringify reproduces stored octets
  const nativeJson = JSON.stringify(record);
  const nativeHash = sha256Hex(nativeJson);
  if (nativeHash === entry.record_hash) {
    console.log(`  PASS: producer[${i}] conformance (JS stringify) (${record.toolName})`);
    passed++;
  } else {
    console.log(`  FAIL: producer[${i}] JS stringify diverges (${record.toolName})`);
    console.log(`    stored:  ${entry.full_record_json}`);
    console.log(`    native:  ${nativeJson}`);
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

// --- Chain with Parties ---
if (vectors.party_attribution?.chain_with_parties) {
  console.log("\n=== Chain with Parties ===\n");

  const cwp = vectors.party_attribution.chain_with_parties;
  for (let i = 0; i < cwp.records.length; i++) {
    const entry = cwp.records[i];
    const record = entry.record;

    const canonical = canonicalizeFromRecord(record, vectors.field_order);
    const canonHash = sha256Hex(canonical);
    if (canonical === entry.canonical && canonHash === entry.sha256_canonical) {
      console.log(`  PASS: chain_with_parties[${i}] canonical (${record.toolName})`);
      passed++;
    } else {
      console.log(`  FAIL: chain_with_parties[${i}] canonical (${record.toolName})`);
      failed++;
    }

    const refHash = sha256Hex(entry.full_record_json);
    if (refHash === entry.record_hash) {
      console.log(`  PASS: chain_with_parties[${i}] record_hash (${record.toolName})`);
      passed++;
    } else {
      console.log(`  FAIL: chain_with_parties[${i}] record_hash (${record.toolName})`);
      console.log(`    expected: ${entry.record_hash}`);
      console.log(`    got:      ${refHash}`);
      failed++;
    }

    let linkageOk;
    if (i === 0) {
      linkageOk = record.previousHash === cwp.genesis_seed;
    } else {
      const prev = cwp.records[i - 1];
      linkageOk =
        record.previousHash === prev.record_hash &&
        entry.previous_record_hash === prev.record_hash;
    }
    if (linkageOk) {
      console.log(`  PASS: chain_with_parties[${i}] linkage (${record.toolName})`);
      passed++;
    } else {
      console.log(`  FAIL: chain_with_parties[${i}] linkage (${record.toolName})`);
      failed++;
    }
  }
}

// --- Scope Order Significance ---
if (vectors.party_attribution) {
  const paVecs = vectors.party_attribution.vectors;
  const origVec = paVecs.find((v) => v.name === "scope_order_original");
  const sortVec = paVecs.find((v) => v.name === "scope_order_sorted");
  if (origVec && sortVec) {
    console.log("\n=== Scope Order Significance ===\n");
    const hOrig = sha256Hex(canonicalizeFromRecord(origVec.record, vectors.field_order));
    const hSort = sha256Hex(canonicalizeFromRecord(sortVec.record, vectors.field_order));
    if (hOrig !== hSort) {
      console.log("  PASS: different scope order produces different hash");
      passed++;
    } else {
      console.log("  FAIL: scope order should produce different hashes");
      failed++;
    }
  }
}


// --- aiInvocation signing vectors ---
if (vectors.ai_invocation_signing) {
  console.log("\n=== aiInvocation Signing ===\n");
  for (const v of vectors.ai_invocation_signing.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    if (canonical === v.canonical) { console.log(`  PASS: ${v.name} canonical form`); passed++; }
    else { console.log(`  FAIL: ${v.name} canonical form`); failed++; }
    if (sha256Hex(canonical) === v.sha256_canonical) { console.log(`  PASS: ${v.name} digest`); passed++; }
    else { console.log(`  FAIL: ${v.name} digest`); failed++; }
  }
  const mn = vectors.ai_invocation_signing.mutation_negative;
  const hOrig = sha256Hex(canonicalizeFromRecord(mn.original.record, vectors.field_order));
  const hMut = sha256Hex(canonicalizeFromRecord(mn.mutated.record, vectors.field_order));
  if (hOrig === mn.original.sha256_canonical && hMut === mn.mutated.sha256_canonical) {
    console.log("  PASS: mutation pair digests reproduce"); passed++;
  } else { console.log("  FAIL: mutation pair digests reproduce"); failed++; }
  if (hOrig !== hMut) { console.log("  PASS: mutated aiInvocation changes signing digest"); passed++; }
  else { console.log("  FAIL: mutated aiInvocation must change signing digest"); failed++; }
}

// --- extensionsDigest base-suite vectors ---
if (vectors.extensions_digest_base) {
  console.log("\n=== extensionsDigest (base suite) ===\n");
  for (const v of vectors.extensions_digest_base.vectors) {
    const canonical = canonicalizeFromRecord(v.record, vectors.field_order);
    if (canonical === v.canonical) { console.log(`  PASS: ${v.name} canonical form`); passed++; }
    else { console.log(`  FAIL: ${v.name} canonical form`); failed++; }
    if (sha256Hex(canonical) === v.sha256_canonical) { console.log(`  PASS: ${v.name} digest`); passed++; }
    else { console.log(`  FAIL: ${v.name} digest`); failed++; }
  }
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);

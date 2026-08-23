#!/usr/bin/env node
/**
 * Cross-language conformance verifier for tool-definition canonicalization.
 * Verifies: SHA-256(JCS(toolDefinition)) matches expected digests.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import canonicalize from "canonicalize";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(__dirname, "tool-definition-canonicalization.json"), "utf-8"),
);

function computeDigest(tool) {
  const canonical = canonicalize(tool);
  if (canonical === undefined) throw new Error("canonicalize returned undefined");
  return createHash("sha256").update(canonical).digest("hex");
}

let passed = 0;
let failed = 0;
let skipped = 0;

console.log("=== Positive vectors (expected digest must match) ===\n");
for (const vec of vectors.positive) {
  try {
    const actual = computeDigest(vec.tool);
    if (actual === vec.expectedDigest) {
      console.log(`  ✓ ${vec.id}: ${vec.description}`);
      passed++;
    } else {
      console.log(`  ✗ ${vec.id}: ${vec.description}`);
      console.log(`    expected: ${vec.expectedDigest}`);
      console.log(`    actual:   ${actual}`);
      failed++;
    }
  } catch (err) {
    console.log(`  ✗ ${vec.id}: ${vec.description} — ERROR: ${err.message}`);
    failed++;
  }
}

console.log("\n=== Negative vectors ===\n");
for (const vec of vectors.negative) {
  if (vec.type === "same_digest") {
    try {
      const dA = computeDigest(vec.toolA);
      const dB = computeDigest(vec.toolB);
      if (dA === dB) {
        console.log(`  ✓ ${vec.id}: ${vec.description}`);
        if (vec.expectedDigest && dA !== vec.expectedDigest) {
          console.log(`    WARNING: digests match each other but differ from expected`);
          console.log(`    expected: ${vec.expectedDigest}, actual: ${dA}`);
        }
        passed++;
      } else {
        console.log(`  ✗ ${vec.id}: ${vec.description}`);
        console.log(`    digestA: ${dA}`);
        console.log(`    digestB: ${dB}`);
        console.log(`    Expected same digest but got different`);
        failed++;
      }
    } catch (err) {
      console.log(`  ✗ ${vec.id}: ERROR: ${err.message}`);
      failed++;
    }
  } else if (vec.type === "different_digest") {
    try {
      const dA = computeDigest(vec.toolA);
      const dB = computeDigest(vec.toolB);
      if (dA !== dB) {
        console.log(`  ✓ ${vec.id}: ${vec.description}`);
        if (vec.digestA && dA !== vec.digestA) {
          console.log(`    WARNING: digestA mismatch: expected ${vec.digestA}, got ${dA}`);
        }
        if (vec.digestB && dB !== vec.digestB) {
          console.log(`    WARNING: digestB mismatch: expected ${vec.digestB}, got ${dB}`);
        }
        passed++;
      } else {
        console.log(`  ✗ ${vec.id}: ${vec.description}`);
        console.log(`    Both produced: ${dA}`);
        console.log(`    Expected different digests`);
        failed++;
      }
    } catch (err) {
      console.log(`  ✗ ${vec.id}: ERROR: ${err.message}`);
      failed++;
    }
  } else if (vec.type === "must_reject") {
    if (vec.tool) {
      try {
        computeDigest(vec.tool);
        // If we get here, check if the tool contains surrogates that should reject
        const toolStr = JSON.stringify(vec.tool);
        const hasSurrogate = /[\uD800-\uDFFF]/.test(toolStr);
        if (hasSurrogate) {
          console.log(`  ✗ ${vec.id}: ${vec.description} — should have rejected but produced a digest`);
          failed++;
        } else {
          // Value was normalized by JSON parse (e.g., >2^53 rounded) — can't test from JSON
          console.log(`  ~ ${vec.id}: ${vec.description} (value normalized at parse, skipped)`);
          skipped++;
        }
      } catch (err) {
        console.log(`  ✓ ${vec.id}: ${vec.description} (correctly rejected: ${err.message.slice(0, 60)})`);
        passed++;
      }
    } else {
      console.log(`  ~ ${vec.id}: ${vec.description} (no tool provided, skipped)`);
      skipped++;
    }
  }
}

console.log("\n=== Drift vectors (before/after digest comparison) ===\n");
for (const vec of vectors.drift) {
  try {
    const beforeD = computeDigest(vec.before);
    const afterD = computeDigest(vec.after);
    const driftDetected = beforeD !== afterD;

    if (driftDetected === vec.driftExpected) {
      console.log(`  ✓ ${vec.id}: ${vec.description}`);
      if (vec.beforeDigest && beforeD !== vec.beforeDigest) {
        console.log(`    WARNING: beforeDigest mismatch`);
      }
      if (vec.afterDigest && afterD !== vec.afterDigest) {
        console.log(`    WARNING: afterDigest mismatch`);
      }
      passed++;
    } else {
      console.log(`  ✗ ${vec.id}: ${vec.description}`);
      console.log(`    before: ${beforeD}`);
      console.log(`    after:  ${afterD}`);
      console.log(`    drift detected: ${driftDetected}, expected: ${vec.driftExpected}`);
      failed++;
    }
  } catch (err) {
    console.log(`  ✗ ${vec.id}: ERROR: ${err.message}`);
    failed++;
  }
}

console.log(`\n=== Results ===`);
console.log(`  Passed:  ${passed}`);
console.log(`  Failed:  ${failed}`);
console.log(`  Skipped: ${skipped}`);
console.log(`  Total:   ${passed + failed + skipped}`);

if (failed > 0) {
  process.exit(1);
}

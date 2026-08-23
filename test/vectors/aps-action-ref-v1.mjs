#!/usr/bin/env node
/**
 * APS action-ref-v1 conformance runner.
 * Adapted from: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/fixtures/cross-stack/action-ref-v1-negatives
 *
 * Tests JCS (RFC 8785) canonical recomputation and fail-closed digest comparison.
 * No APS SDK dependency — uses the same SHA-256 + canonical-sort primitives
 * that back our attestation layer.
 *
 * Property under test: a verifier recomputes action_ref from the invocation
 * payload exactly once via JCS canonicalization, then rejects on mismatch.
 * No retries, no coercion, no normalization.
 *
 * Scope relative to the full APS conformance suite: we extract the fail-closed
 * digest recomputation property, which our attestation layer shares. The
 * aae-envelope interop vectors test delegation chain semantics (scope narrowing,
 * expiry cascade, revocation cascade) that this system does not implement — we
 * provide audit trail attestation, not delegation verification. The one
 * aae-envelope concept that applies is signature substitution (valid signature
 * from key A rejected when verified against key B), tested directly in
 * src/attestation/signer.test.ts.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(__dirname, "aps-action-ref-v1-vectors.json"), "utf8")
);

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// RFC 8785 (JCS) for flat objects: keys sorted lexicographically,
// values serialized per ECMA-262. For these fixtures all values are
// strings or safe integers.
function jcsFlat(obj) {
  const parts = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${jcsValue(obj[k])}`);
  return `{${parts.join(",")}}`;
}

function jcsValue(v) {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return String(v);
  throw new Error(`jcsFlat: unsupported value type for ${JSON.stringify(v)}`);
}

// Canonical timestamp grammar: RFC 3339 UTC, exactly three fractional digits, Z suffix.
const CANONICAL_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// Single-path verifier: grammar gate, one recomputation, one comparison.
function verifyClaim(payload, claimedActionRef) {
  for (const field of ["action_type", "agent_id", "scope", "timestamp"]) {
    if (!(field in payload)) {
      return { ok: false, stage: "grammar", reason: `missing field: ${field}` };
    }
  }
  const ts = payload.timestamp;
  if (typeof ts !== "string" || !CANONICAL_TS.test(ts)) {
    return { ok: false, stage: "grammar", reason: "timestamp grammar rejected" };
  }
  const recomputed = sha256hex(jcsFlat(payload));
  if (recomputed !== claimedActionRef) {
    return { ok: false, stage: "recompute", reason: "digest mismatch", recomputed };
  }
  return { ok: true, stage: "recompute", reason: "match", recomputed };
}

let passed = 0;
let failed = 0;

function check(condition, name, detail) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${name}`);
  } else {
    failed++;
    console.log(`  FAIL: ${name}`);
    if (detail) console.log(`        ${detail}`);
  }
}

// === Positive vectors: recomputation must match ===
console.log("\n=== action-ref-v1 Positive Recomputation ===");
for (const v of fixture.positive_fixture.vectors) {
  const jcs = jcsFlat(v.preimage);
  check(
    jcs === v.jcs_payload,
    `${v.id} JCS canonical form`,
    `expected: ${v.jcs_payload}\n        got:      ${jcs}`
  );

  const digest = sha256hex(jcs);
  check(
    digest === v.action_ref,
    `${v.id} SHA-256 recomputation`,
    `expected: ${v.action_ref}\n        got:      ${digest}`
  );

  const verdict = verifyClaim(v.preimage, v.action_ref);
  check(verdict.ok, `${v.id} verifier accepts`);
}

// === Negative vectors: must fail-closed ===
console.log("\n=== action-ref-v1 Negative (Fail-Closed) ===");
const stageMap = { grammar_reject: "grammar", recompute_mismatch: "recompute" };

for (const v of fixture.negative_fixture.vectors) {
  const verdict = verifyClaim(v.invocation_payload, v.claimed_action_ref);
  const expectedStage = stageMap[v.expected_failure_stage];

  check(
    !verdict.ok,
    `${v.id} rejected`,
    verdict.ok ? "verifier accepted (BUG)" : undefined
  );
  check(
    verdict.stage === expectedStage,
    `${v.id} failure stage = ${expectedStage}`,
    `got: ${verdict.stage}`
  );

  // Fixture integrity: drifted digest is byte-derived (not invented)
  const drifted = v.drifted_serialization ?? v.drifted_jcs_payload;
  if (drifted) {
    check(
      sha256hex(drifted) === v.claimed_action_ref,
      `${v.id} fixture integrity (drifted digest is real)`
    );
  }

  // Invariant: claimed != correct (they're genuinely different digests)
  check(
    v.claimed_action_ref !== v.correct_action_ref,
    `${v.id} invariant (claimed != correct)`
  );
}

// === Summary ===
console.log(`\n=== Results: ${passed} passed, ${failed} failed (${passed + failed} total) ===`);
process.exit(failed > 0 ? 1 : 0);

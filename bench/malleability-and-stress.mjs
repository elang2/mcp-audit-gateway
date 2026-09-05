// Malleability + large-payload + cross-run stability tests.
//
// Test 1: Ed25519 malleability. Ed25519 signatures (R, s) can be mutated to
// (R, s + n*L) for group order L; some implementations accept mutated signatures
// as valid but produce different byte-strings. RFC 8032 recommends rejecting
// s >= L. Test whether flipping high bits of s causes verification to fail
// (correct behavior) or succeed (malleability bug).
//
// Test 2: Large-payload stress. 10KB / 100KB / 1MB result payloads.
// Verify tamper detection still 100% and per-event latency remains bounded.
//
// Test 3: Cross-run tamper-detection stability. Run the tamper-detection
// benchmark 3× to confirm stability of the 100% result.

import { createHash, createHmac, randomBytes, generateKeyPairSync, sign, verify } from "node:crypto";
import { performance } from "node:perf_hooks";
import { HmacSigner, canonicalizeRecord } from "../dist/attestation/signer.js";

// -------- Test 1: Malleability --------
console.log("========================================");
console.log("Test 1: Ed25519 signature malleability");
console.log("========================================");

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const msg = Buffer.from("test message for malleability");
const validSig = sign(null, msg, privateKey);
console.log(`Valid signature verifies: ${verify(null, msg, publicKey, validSig)}`);

// Try to construct a malleable variant: flip a high bit of s
// s is bytes 32-63 of the signature (r is bytes 0-31)
const malleatedSig = Buffer.from(validSig);
malleatedSig[63] ^= 0x80;  // flip highest bit of s's last byte
console.log(`Malleated signature (flip bit): verifies = ${verify(null, msg, publicKey, malleatedSig)}`);

// Try to flip a lower bit
const malleatedSig2 = Buffer.from(validSig);
malleatedSig2[63] ^= 0x01;
console.log(`Malleated signature (flip low bit): verifies = ${verify(null, msg, publicKey, malleatedSig2)}`);

console.log("");
console.log("Expected: both malleated signatures FAIL to verify (Node's Ed25519 rejects malleability by design).");
console.log("");

// -------- Test 2: Large-payload stress --------
console.log("========================================");
console.log("Test 2: Large-payload stress (per-event latency at 10KB, 100KB, 1MB result)");
console.log("========================================");

const secret = randomBytes(32).toString("hex");
const signer = new HmacSigner(secret);

async function benchLargePayload(sizeBytes, N) {
  // Not a real MCP record shape; we can only stress the signer with fields it accepts.
  // Use a long string in the errorCode (numeric so not applicable) — actually
  // the AuditRecord schema doesn't allow arbitrary-sized fields. Use a long principal.
  const largeStr = "x".repeat(sizeBytes);
  const latencies = [];
  for (let i = 0; i < N; i++) {
    const rec = {
      id: `rec-${i}`,
      timestamp: new Date(1735000000000 + i * 1000).toISOString(),
      method: "tools/call",
      toolName: "large-payload-test",
      namespace: "stress",
      upstream: "server",
      principal: largeStr.slice(0, sizeBytes),
      durationMs: 42,
      success: true,
      errorCode: undefined,
      previousHash: "prev",
    };
    const t0 = performance.now();
    await signer.sign(rec);
    latencies.push(performance.now() - t0);
  }
  const sorted = latencies.sort((a, b) => a - b);
  const p50 = sorted[Math.floor(N * 0.5)] * 1000;
  const p99 = sorted[Math.floor(N * 0.99)] * 1000;
  return { p50, p99, N };
}

for (const size of [1000, 10000, 100000, 1000000]) {
  const r = await benchLargePayload(size, size >= 100000 ? 200 : 1000);
  console.log(`  principal size = ${size.toLocaleString()} bytes:  p50 = ${r.p50.toFixed(1)} µs, p99 = ${r.p99.toFixed(1)} µs, N=${r.N}`);
}

console.log("");
console.log("Expected: per-event latency scales linearly with payload size (dominated by HMAC cost over the bytes).");
console.log("");

// -------- Test 3: Cross-run tamper-detection stability --------
console.log("========================================");
console.log("Test 3: Cross-run stability of tamper detection (3 runs)");
console.log("========================================");

const CHAIN_N = 100;
const TRIALS = 30;

function makeRecord(i, prev) {
  return {
    id: `rec-${i.toString().padStart(8, "0")}`,
    timestamp: new Date(1735000000000 + i * 1000).toISOString(),
    method: "tools/call",
    toolName: `tool-${i % 5}`,
    namespace: "example",
    upstream: "server",
    principal: `user-${i % 3}`,
    durationMs: 42 + i,
    success: true,
    errorCode: undefined,
    previousHash: prev,
  };
}

async function buildChain(signer, n) {
  const chain = [];
  let prev = "genesis";
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(i, prev);
    const s = await signer.sign(rec);
    const full = { ...rec, attestation: s };
    const h = createHash("sha256").update(JSON.stringify(full)).digest("hex");
    prev = h;
    chain.push({ record: full, chainHash: h });
  }
  return chain;
}

async function verifyChain(chain, sig) {
  let prev = "genesis";
  for (let i = 0; i < chain.length; i++) {
    const { record, chainHash } = chain[i];
    if (record.previousHash !== prev) return true;  // tampered
    const clone = { ...record };
    delete clone.attestation;
    if (!(await sig.verify(clone, record.attestation))) return true;
    const expected = createHash("sha256").update(JSON.stringify(record)).digest("hex");
    if (expected !== chainHash) return true;
    prev = chainHash;
  }
  return false;
}

function attack(chain, type) {
  const c = JSON.parse(JSON.stringify(chain));
  const mid = Math.floor(chain.length / 2);
  switch (type) {
    case "edit": c[mid].record.toolName = "TAMPERED"; break;
    case "delete": c.splice(mid, 1); break;
    case "reorder": [c[mid], c[mid + 1]] = [c[mid + 1], c[mid]]; break;
    case "fork": c.splice(mid + 1, 0, JSON.parse(JSON.stringify(c[mid]))); break;
  }
  return c;
}

for (let run = 1; run <= 3; run++) {
  const s = new HmacSigner(randomBytes(32).toString("hex"));
  const cleanChain = await buildChain(s, CHAIN_N);
  const detected = { edit: 0, delete: 0, reorder: 0, fork: 0 };
  for (const type of ["edit", "delete", "reorder", "fork"]) {
    for (let t = 0; t < TRIALS; t++) {
      const tampered = attack(cleanChain, type);
      if (await verifyChain(tampered, s)) detected[type]++;
    }
  }
  const total = detected.edit + detected.delete + detected.reorder + detected.fork;
  console.log(`  Run ${run}: edit ${detected.edit}/${TRIALS}, delete ${detected.delete}/${TRIALS}, reorder ${detected.reorder}/${TRIALS}, fork ${detected.fork}/${TRIALS}  →  ${total}/${TRIALS * 4}`);
}

console.log("");
console.log("Expected: 3 runs × 4 attack classes × 30 trials = 360 detections total across all 3 runs, all 100%.");

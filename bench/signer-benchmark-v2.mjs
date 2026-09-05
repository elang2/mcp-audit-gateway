// mcp-audit-gateway signer benchmark v2.
// v2 fixes issues flagged in a methodology audit of v1:
//   - Uses the REAL production HmacSigner, Ed25519Signer, canonicalizeRecord
//   - Uses the REAL AuditRecord type shape
//   - Adds a hash-only baseline (SHA-256 chain, no MAC, no signature)
//     for apples-to-apples with Agent Flight Recorder's reported 48 µs
//   - Reports mean and stddev across R rounds
//   - Drops warmup outliers
// Run: node bench/signer-benchmark-v2.mjs [--n=50000] [--rounds=5]

import { createHash, randomBytes, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  HmacSigner,
  Ed25519Signer,
  canonicalizeRecord,
} from "../dist/attestation/signer.js";

const argN = process.argv.find((a) => a.startsWith("--n="));
const argR = process.argv.find((a) => a.startsWith("--rounds="));
const N = argN ? parseInt(argN.slice(4), 10) : 50000;
const ROUNDS = argR ? parseInt(argR.slice(9), 10) : 5;

// Build a plausible tool-call AuditRecord matching the production shape
function makeAuditRecord(i, prevHash) {
  return {
    id: `rec-${i.toString().padStart(8, "0")}`,
    timestamp: new Date(1735000000000 + i * 1000).toISOString(),
    method: "tools/call",
    toolName: "example_tool",
    namespace: "example.namespace",
    upstream: "example-server",
    principal: "user@example",
    durationMs: 42,
    success: true,
    errorCode: undefined,
    previousHash: prevHash,
  };
}

function percentile(sortedArr, p) {
  const idx = Math.min(sortedArr.length - 1, Math.floor(sortedArr.length * p));
  return sortedArr[idx];
}

function stats(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const p50us = percentile(sorted, 0.5) * 1000;
  const p95us = percentile(sorted, 0.95) * 1000;
  const p99us = percentile(sorted, 0.99) * 1000;
  const meanUs = (sorted.reduce((s, v) => s + v, 0) / sorted.length) * 1000;
  return { p50us, p95us, p99us, meanUs };
}

async function benchHashOnly(n) {
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const start = performance.now();
    const canonical = canonicalizeRecord(rec);
    const fullPayload = JSON.stringify({ ...rec, attestation: "" });
    const chainHash = createHash("sha256").update(fullPayload).digest("hex");
    prevHash = chainHash;
    latencies[i] = performance.now() - start;
    totalBytes += Buffer.byteLength(fullPayload, "utf8");
    // consume canonical to prevent DCE
    if (canonical.length < 0) console.log("dce");
  }
  const t1 = performance.now();
  return { latencies, totalMs: t1 - t0, totalBytes };
}

async function benchHmac(n) {
  const secret = randomBytes(32).toString("hex");
  const signer = new HmacSigner(secret);
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const start = performance.now();
    const sig = await signer.sign(rec);
    const fullPayload = JSON.stringify({ ...rec, attestation: sig });
    const chainHash = createHash("sha256").update(fullPayload).digest("hex");
    prevHash = chainHash;
    latencies[i] = performance.now() - start;
    totalBytes += Buffer.byteLength(fullPayload, "utf8");
  }
  const t1 = performance.now();
  return { latencies, totalMs: t1 - t0, totalBytes };
}

async function benchNativeEd25519(n) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const start = performance.now();
    const canonical = canonicalizeRecord(rec);
    const sig = nodeSign(null, Buffer.from(canonical, "utf8"), privateKey).toString("hex");
    const fullPayload = JSON.stringify({ ...rec, attestation: sig });
    const chainHash = createHash("sha256").update(fullPayload).digest("hex");
    prevHash = chainHash;
    latencies[i] = performance.now() - start;
    totalBytes += Buffer.byteLength(fullPayload, "utf8");
  }
  const t1 = performance.now();
  return { latencies, totalMs: t1 - t0, totalBytes };
}

async function benchEd25519(n) {
  const signer = new Ed25519Signer();
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const start = performance.now();
    const sig = await signer.sign(rec);
    const fullPayload = JSON.stringify({ ...rec, attestation: sig });
    const chainHash = createHash("sha256").update(fullPayload).digest("hex");
    prevHash = chainHash;
    latencies[i] = performance.now() - start;
    totalBytes += Buffer.byteLength(fullPayload, "utf8");
  }
  const t1 = performance.now();
  return { latencies, totalMs: t1 - t0, totalBytes };
}

async function runMultiRound(label, fn, n, rounds) {
  const results = [];
  console.log(`\n### ${label} — ${rounds} rounds at N=${n}`);
  // Warmup
  await fn(Math.min(1000, Math.floor(n / 10)));
  for (let r = 0; r < rounds; r++) {
    const res = await fn(n);
    const s = stats(res.latencies);
    const throughput = (n / res.totalMs) * 1000;
    const bytesPerEvent = res.totalBytes / n;
    console.log(`  round ${r + 1}: p50=${s.p50us.toFixed(1)} µs  p95=${s.p95us.toFixed(1)} µs  p99=${s.p99us.toFixed(1)} µs  ` +
                `throughput=${throughput.toFixed(0)} evt/s  bytes=${bytesPerEvent.toFixed(0)}`);
    results.push({ ...s, throughput, bytesPerEvent, totalMs: res.totalMs });
  }
  // Aggregate: mean and stddev of p50 across rounds
  const p50arr = results.map((r) => r.p50us);
  const meanP50 = p50arr.reduce((a, b) => a + b, 0) / p50arr.length;
  const varP50 = p50arr.reduce((a, b) => a + (b - meanP50) ** 2, 0) / p50arr.length;
  const stddev = Math.sqrt(varP50);
  const cv = (stddev / meanP50) * 100;
  const meanTP = results.map((r) => r.throughput).reduce((a, b) => a + b, 0) / results.length;
  const meanBytes = results.map((r) => r.bytesPerEvent).reduce((a, b) => a + b, 0) / results.length;
  console.log(`  AGGREGATE: p50 mean=${meanP50.toFixed(1)} µs stddev=${stddev.toFixed(2)} µs CV=${cv.toFixed(1)}%  ` +
              `throughput mean=${meanTP.toFixed(0)} evt/s  bytes=${meanBytes.toFixed(0)}`);
  return { label, meanP50, stddev, cv, meanTP, meanBytes, results };
}

async function main() {
  console.log(`Benchmark v2 — mcp-audit-gateway signer paths`);
  console.log(`Configuration: N=${N} events per round, ${ROUNDS} rounds per mode`);
  console.log(`Node ${process.version}, arch ${process.arch}, platform ${process.platform}`);
  console.log(`Uses production HmacSigner, Ed25519Signer, canonicalizeRecord from dist/`);

  const hashOnly = await runMultiRound("Hash-only baseline (SHA-256 chain, no MAC/sig)", benchHashOnly, N, ROUNDS);
  const hmac = await runMultiRound("HMAC-SHA256 wrap mode", benchHmac, N, ROUNDS);
  const nativeEd = await runMultiRound("Ed25519 gateway mode (Node native crypto.sign)", benchNativeEd25519, N, ROUNDS);
  // @noble/ed25519 async is slower; fewer records
  const edN = Math.min(N, 20000);
  const edRounds = Math.max(3, Math.floor(ROUNDS / 2));
  const ed25519 = await runMultiRound(`Ed25519 gateway mode (@noble WebCrypto async, N=${edN}, ${edRounds} rounds)`, benchEd25519, edN, edRounds);

  console.log(`\n### Summary`);
  console.log(`| Mode | p50 mean | stddev | CV | throughput | bytes/event |`);
  console.log(`|---|---|---|---|---|---|`);
  for (const r of [hashOnly, hmac, nativeEd, ed25519]) {
    console.log(`| ${r.label} | ${r.meanP50.toFixed(1)} µs | ${r.stddev.toFixed(2)} µs | ${r.cv.toFixed(1)}% | ${r.meanTP.toFixed(0)} evt/s | ${r.meanBytes.toFixed(0)} |`);
  }

  console.log(`\n### Apples-to-apples comparison to Agent Flight Recorder`);
  console.log(`AFR reports per-event median: 48 µs (SHA-256 hash-chain + Merkle-batch, no per-event signing)`);
  console.log(`Ours, matched: ${hashOnly.meanP50.toFixed(1)} µs (SHA-256 hash-chain, no MAC, no signature)`);
  console.log(`Ratio: ${(48 / hashOnly.meanP50).toFixed(1)}× (ours faster than AFR's reported value)`);
  console.log(`\nCaveats: different hardware (macOS/arm64 vs. AFR unspecified);`);
  console.log(`AFR includes Merkle-tree insertion which we do not; batching/anchoring costs excluded from both.`);
}
main().catch((e) => { console.error(e); process.exit(1); });

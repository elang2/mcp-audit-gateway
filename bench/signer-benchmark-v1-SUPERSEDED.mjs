// Micro-benchmark for mcp-audit-gateway signer + hash chain paths.
// Measures per-event latency (p50/p95/p99), throughput, and bytes-per-event.
// Compares Ed25519 gateway mode against HMAC-SHA256 wrap mode.
// Run: node bench/signer-benchmark.mjs [--n=100000]

import { createHash, createHmac, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import * as ed from "@noble/ed25519";
// v2.3 signAsync/getPublicKeyAsync use WebCrypto internally; no SHA-512 wiring needed

const argN = process.argv.find((a) => a.startsWith("--n="));
const N = argN ? parseInt(argN.slice(4), 10) : 100000;

// Build a plausible tool-call audit record shape
function makeRecord(i, prevHash) {
  return {
    version: 1,
    recordId: `rec-${i.toString().padStart(8, "0")}`,
    timestamp: new Date(Date.now() + i).toISOString(),
    sessionId: "sess-benchmark",
    toolName: "example_tool",
    args: { query: `benchmark-request-${i}`, limit: 100 },
    result: { ok: true, data: [1, 2, 3] },
    durationMs: 42,
    success: true,
    previousHash: prevHash,
  };
}

// Canonical serializer (matches signer.ts approach: fixed-order tuple array)
const FIELD_ORDER = [
  "version",
  "recordId",
  "timestamp",
  "sessionId",
  "toolName",
  "args",
  "result",
  "durationMs",
  "success",
  "previousHash",
];
function canonicalize(record) {
  const tuple = FIELD_ORDER.map((k) => [k, record[k] ?? null]);
  return JSON.stringify(tuple);
}

function percentile(sortedArr, p) {
  const idx = Math.min(sortedArr.length - 1, Math.floor(sortedArr.length * p));
  return sortedArr[idx];
}

async function benchHmac(n) {
  const secret = randomBytes(32);
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(i, prevHash);
    const start = performance.now();
    const payload = canonicalize(rec);
    const sig = createHmac("sha256", secret).update(payload).digest("hex");
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
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const latencies = new Float64Array(n);
  let prevHash = "genesis";
  let totalBytes = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(i, prevHash);
    const start = performance.now();
    const payload = canonicalize(rec);
    const sig = await ed.signAsync(new TextEncoder().encode(payload), privateKey);
    const sigHex = Buffer.from(sig).toString("hex");
    const fullPayload = JSON.stringify({ ...rec, attestation: sigHex });
    const chainHash = createHash("sha256").update(fullPayload).digest("hex");
    prevHash = chainHash;
    latencies[i] = performance.now() - start;
    totalBytes += Buffer.byteLength(fullPayload, "utf8");
  }
  const t1 = performance.now();
  return { latencies, totalMs: t1 - t0, totalBytes };
}

function report(label, r, n) {
  const sorted = Array.from(r.latencies).sort((a, b) => a - b);
  const p50us = percentile(sorted, 0.5) * 1000;
  const p95us = percentile(sorted, 0.95) * 1000;
  const p99us = percentile(sorted, 0.99) * 1000;
  const meanUs = (sorted.reduce((s, v) => s + v, 0) / sorted.length) * 1000;
  const throughput = (n / r.totalMs) * 1000;
  const avgBytes = r.totalBytes / n;
  console.log(`\n=== ${label} (N=${n}) ===`);
  console.log(`  latency:    p50=${p50us.toFixed(1)} µs  p95=${p95us.toFixed(1)} µs  p99=${p99us.toFixed(1)} µs  mean=${meanUs.toFixed(1)} µs`);
  console.log(`  throughput: ${throughput.toFixed(0)} events/sec`);
  console.log(`  bytes/event: ${avgBytes.toFixed(0)} bytes (canonical payload + sig + chain metadata)`);
  console.log(`  total wall: ${r.totalMs.toFixed(0)} ms`);
}

async function main() {
  console.log(`Benchmarking mcp-audit-gateway signer paths, N=${N}`);
  console.log(`Node ${process.version}, arch ${process.arch}, platform ${process.platform}`);
  console.log(`\nWarming up...`);
  await benchHmac(1000);
  await benchEd25519(1000);
  console.log(`\nRunning...`);
  const hmacResult = await benchHmac(N);
  report("HMAC-SHA256 wrap mode", hmacResult, N);
  const edResult = await benchEd25519(N);
  report("Ed25519 gateway mode", edResult, N);
  console.log("\n=== Comparison to Agent Flight Recorder (Bindschaedler et al., binds.ch) ===");
  console.log(`  AFR reports: 48 µs median per-event latency, 512 bytes per event`);
  console.log(`  (AFR uses on-chain L2 anchoring at $2.30 per 100K events; this benchmark uses zero-infra chaining)`);
}
main().catch((e) => { console.error(e); process.exit(1); });

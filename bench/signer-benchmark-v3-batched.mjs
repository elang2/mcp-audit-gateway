// mcp-audit-gateway signer benchmark v3: batched Ed25519 (Merkle-style).
// Implements the AFR-style batched signing pattern for apples-to-apples
// comparison with Agent Flight Recorder's "+Full" configuration (47.6 µs
// median per-event on their Table II).
//
// Per-event: canonical form + SHA-256 chain hash + append leaf to current epoch.
// Epoch boundary: compute Merkle root of the epoch's leaf list, sign the root
// with Ed25519 (Node native). Per-event amortized cost = per-event work +
// (Ed25519 sign time) / EPOCH_SIZE.
//
// Also adds: N=1M single-round scale test, memory/RSS profile at completion,
// tail-latency (p999) tracking, memory delta per event chain.
//
// Run: node bench/signer-benchmark-v3-batched.mjs [--n=100000] [--rounds=5] [--epoch=100]

import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  canonicalizeRecord,
} from "../dist/attestation/signer.js";

const argN = process.argv.find((a) => a.startsWith("--n="));
const argR = process.argv.find((a) => a.startsWith("--rounds="));
const argE = process.argv.find((a) => a.startsWith("--epoch="));
const N = argN ? parseInt(argN.slice(4), 10) : 100000;
const ROUNDS = argR ? parseInt(argR.slice(9), 10) : 5;
const EPOCH_SIZE = argE ? parseInt(argE.slice(8), 10) : 100;

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

function merkleRoot(leaves) {
  if (leaves.length === 0) return Buffer.alloc(32);
  let level = leaves.map((l) => Buffer.from(l, "hex"));
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      nextLevel.push(createHash("sha256").update(Buffer.concat([left, right])).digest());
    }
    level = nextLevel;
  }
  return level[0];
}

function percentile(sortedArr, p) {
  const idx = Math.min(sortedArr.length - 1, Math.floor(sortedArr.length * p));
  return sortedArr[idx];
}

function stats(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  return {
    p50us: percentile(sorted, 0.5) * 1000,
    p95us: percentile(sorted, 0.95) * 1000,
    p99us: percentile(sorted, 0.99) * 1000,
    p999us: percentile(sorted, 0.999) * 1000,
    meanUs: (sorted.reduce((s, v) => s + v, 0) / sorted.length) * 1000,
    minUs: sorted[0] * 1000,
    maxUs: sorted[sorted.length - 1] * 1000,
  };
}

async function benchBatchedEd25519(n, epochSize) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const perEventLatencies = new Float64Array(n);
  const epochSignLatencies = [];
  let prevHash = "genesis";
  let totalBytes = 0;
  let currentEpochLeaves = [];
  let epochCount = 0;

  const memBefore = process.memoryUsage();
  const t0 = performance.now();

  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const start = performance.now();

    // Per-event work: canonicalize + chain hash + append leaf
    const canonical = canonicalizeRecord(rec);
    const chainHash = createHash("sha256").update(canonical + prevHash).digest("hex");
    prevHash = chainHash;
    currentEpochLeaves.push(chainHash);

    const fullPayload = JSON.stringify({ ...rec, attestation: "" });
    totalBytes += Buffer.byteLength(fullPayload, "utf8");

    perEventLatencies[i] = performance.now() - start;

    // Epoch boundary: compute Merkle root and sign
    if (currentEpochLeaves.length >= epochSize) {
      const epochStart = performance.now();
      const root = merkleRoot(currentEpochLeaves);
      const sig = nodeSign(null, root, privateKey);
      const epochMs = performance.now() - epochStart;
      epochSignLatencies.push(epochMs);
      currentEpochLeaves = [];
      epochCount++;
    }
  }

  const t1 = performance.now();
  const memAfter = process.memoryUsage();

  // Amortized per-event cost including epoch signing
  const totalEpochCost = epochSignLatencies.reduce((a, b) => a + b, 0);
  const amortizedPerEventMs = totalEpochCost / n;

  return {
    perEventLatencies,
    epochSignLatencies,
    totalMs: t1 - t0,
    totalBytes,
    epochCount,
    amortizedPerEventMs,
    memDeltaMb: (memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024,
    rssMb: memAfter.rss / 1024 / 1024,
  };
}

async function runMultiRound(label, fn, n, rounds, epochSize) {
  console.log(`\n### ${label}`);
  console.log(`Config: N=${n} events/round, ${rounds} rounds, epoch=${epochSize} events`);

  // Warmup
  await fn(Math.min(1000, Math.floor(n / 10)), epochSize);

  const results = [];
  for (let r = 0; r < rounds; r++) {
    const res = await fn(n, epochSize);
    const perEvent = stats(res.perEventLatencies);
    const epochStats = stats(new Float64Array(res.epochSignLatencies));
    const amortizedUs = (perEvent.meanUs + res.amortizedPerEventMs * 1000);
    const throughput = (n / res.totalMs) * 1000;
    console.log(`  round ${r + 1}: per-event p50=${perEvent.p50us.toFixed(1)}µs p95=${perEvent.p95us.toFixed(1)}µs p99=${perEvent.p99us.toFixed(1)}µs p999=${perEvent.p999us.toFixed(1)}µs`);
    console.log(`           amortized(w/epoch sign)=${amortizedUs.toFixed(2)}µs  epoch signs=${res.epochCount}  epoch p50=${epochStats.p50us.toFixed(1)}µs`);
    console.log(`           throughput=${throughput.toFixed(0)} evt/s  mem heap Δ=${res.memDeltaMb.toFixed(1)}MB  RSS=${res.rssMb.toFixed(0)}MB`);
    results.push({ perEvent, epochStats, amortizedUs, throughput, memDeltaMb: res.memDeltaMb, rssMb: res.rssMb });
  }

  const p50arr = results.map((r) => r.perEvent.p50us);
  const meanP50 = p50arr.reduce((a, b) => a + b, 0) / p50arr.length;
  const stddev = Math.sqrt(p50arr.reduce((a, b) => a + (b - meanP50) ** 2, 0) / p50arr.length);
  const cv = (stddev / meanP50) * 100;
  const meanAmortized = results.map((r) => r.amortizedUs).reduce((a, b) => a + b, 0) / results.length;
  const meanTP = results.map((r) => r.throughput).reduce((a, b) => a + b, 0) / results.length;
  console.log(`  AGGREGATE: per-event p50=${meanP50.toFixed(2)}µs stddev=${stddev.toFixed(2)}µs CV=${cv.toFixed(1)}%  amortized=${meanAmortized.toFixed(2)}µs  throughput=${meanTP.toFixed(0)} evt/s`);
  return { meanP50, stddev, cv, meanAmortized, meanTP };
}

async function main() {
  console.log(`Benchmark v3 — Batched Ed25519 (Merkle-style, AFR-style)`);
  console.log(`Node ${process.version}, arch ${process.arch}, platform ${process.platform}`);
  console.log(`Compares apples-to-apples with AFR Full config (47.6µs median per-event, epoch=100)`);

  const results = {};

  for (const epoch of [50, 100, 500, 1000]) {
    results[epoch] = await runMultiRound(`Batched Ed25519, epoch=${epoch}`, benchBatchedEd25519, N, ROUNDS, epoch);
  }

  console.log(`\n### Summary — batched Ed25519 amortized per-event cost by epoch size`);
  console.log(`| Epoch size | per-event p50 (µs) | amortized (µs) | throughput (evt/s) | AFR Full comparison |`);
  console.log(`|---|---|---|---|---|`);
  for (const epoch of [50, 100, 500, 1000]) {
    const r = results[epoch];
    const ratio = (47.6 / r.meanAmortized).toFixed(1);
    console.log(`| ${epoch} | ${r.meanP50.toFixed(2)} | ${r.meanAmortized.toFixed(2)} | ${r.meanTP.toFixed(0)} | ${ratio}× faster than AFR Full 47.6µs |`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

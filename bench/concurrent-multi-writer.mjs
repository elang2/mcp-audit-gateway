// Concurrent multi-writer benchmark for mcp-audit-gateway.
// Simulates N concurrent principals, each maintaining their own audit chain,
// signing events in parallel via Promise.all batches.
// Reports throughput and per-event latency at 1, 10, 100, 1000 concurrent principals.

import { createHash, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { HmacSigner, canonicalizeRecord } from "../dist/attestation/signer.js";

const EVENTS_PER_PRINCIPAL = 1000;
const CONCURRENCY_LEVELS = [1, 10, 100, 500, 1000];

function makeRecord(pid, i, prev) {
  return {
    id: `p${pid}-rec-${i.toString().padStart(6, "0")}`,
    timestamp: new Date(1735000000000 + i * 1000).toISOString(),
    method: "tools/call",
    toolName: "example_tool",
    namespace: "example",
    upstream: "server",
    principal: `principal-${pid}`,
    durationMs: 42,
    success: true,
    errorCode: undefined,
    previousHash: prev,
  };
}

async function principalChain(pid, n) {
  const signer = new HmacSigner(randomBytes(32).toString("hex"));
  let prev = "genesis";
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(pid, i, prev);
    const sig = await signer.sign(rec);
    const chainHash = createHash("sha256").update(JSON.stringify({ ...rec, attestation: sig })).digest("hex");
    prev = chainHash;
  }
}

async function benchConcurrency(concurrent, eventsPerPrincipal) {
  const t0 = performance.now();
  const promises = [];
  for (let p = 0; p < concurrent; p++) {
    promises.push(principalChain(p, eventsPerPrincipal));
  }
  await Promise.all(promises);
  const wallMs = performance.now() - t0;
  const totalEvents = concurrent * eventsPerPrincipal;
  const throughput = (totalEvents / wallMs) * 1000;
  const perEventUs = (wallMs / totalEvents) * 1000;
  return { concurrent, totalEvents, wallMs, throughput, perEventUs };
}

async function main() {
  console.log(`Concurrent multi-writer benchmark`);
  console.log(`Each principal writes ${EVENTS_PER_PRINCIPAL} events; multiple principals run concurrently via Promise.all`);
  console.log(`Node ${process.version}, arch ${process.arch}\n`);

  // Warmup
  await benchConcurrency(1, 100);

  console.log(`| Concurrent principals | Total events | Wall time (s) | Throughput (evt/s) | Per-event mean (µs) | Speedup vs 1P |`);
  console.log(`|---|---|---|---|---|---|`);

  const results = [];
  for (const c of CONCURRENCY_LEVELS) {
    const r = await benchConcurrency(c, EVENTS_PER_PRINCIPAL);
    results.push(r);
    const baseline = results[0].throughput;
    const speedup = (r.throughput / baseline).toFixed(2);
    console.log(`| ${c} | ${r.totalEvents.toLocaleString()} | ${(r.wallMs/1000).toFixed(2)} | ${r.throughput.toFixed(0)} | ${r.perEventUs.toFixed(2)} | ${speedup}× |`);
  }

  console.log(`\nMemory profile after all runs:`);
  const mem = process.memoryUsage();
  console.log(`  heap used: ${(mem.heapUsed/1024/1024).toFixed(0)} MB`);
  console.log(`  RSS:       ${(mem.rss/1024/1024).toFixed(0)} MB`);
}

main().catch((e) => { console.error(e); process.exit(1); });

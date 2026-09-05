// Measures the per-call overhead of `await import()` inside a hot path
// (matches the `Ed25519Signer.sign()` behavior in shipping signer.ts).
// Confirmed 2026-08-30: 2.34 µs per call after module cache primed.
// Compared to native Ed25519 sign latency 31.9 µs → 7.34% avoidable overhead.
//
// Run:  node bench/dynamic-import-perf.mjs

import { performance } from "node:perf_hooks";

const N = 10000;

// Prime the module cache
for (let i = 0; i < 100; i++) await import("@noble/ed25519");

// Case 1: dynamic import inside hot path (matches signer.ts behavior)
const t0 = performance.now();
for (let i = 0; i < N; i++) {
  const ed = await import("@noble/ed25519");
  const _ = ed.utils; // access to ensure module keys resolve
}
const dynamicPerCall = ((performance.now() - t0) / N) * 1000;

// Case 2: hoisted top-level import (the fix)
const ed = await import("@noble/ed25519");
const t1 = performance.now();
for (let i = 0; i < N; i++) {
  const _ = ed.utils;
}
const topLevelPerCall = ((performance.now() - t1) / N) * 1000;

console.log(`Dynamic import per call (post-cache): ${dynamicPerCall.toFixed(4)} µs`);
console.log(`Top-level import + prop access:       ${topLevelPerCall.toFixed(4)} µs`);
console.log(`Overhead of the pattern:              ${(dynamicPerCall - topLevelPerCall).toFixed(4)} µs per call`);
console.log(``);
console.log(`Comparison to Ed25519 native sign latency (31.9 µs from bench v2):`);
console.log(`  Import overhead / sign latency = ${((dynamicPerCall - topLevelPerCall) / 31.9 * 100).toFixed(2)}%`);

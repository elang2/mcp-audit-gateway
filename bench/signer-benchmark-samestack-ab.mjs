// Same-stack A/B: batched Ed25519 vs. single-sign Ed25519, both in Node.js/OpenSSL/JCS.
//
// This isolates the BATCHING claim by controlling for:
//   - Runtime: both use Node.js (v22.x) with V8
//   - Crypto backend: both use node:crypto sign() with OpenSSL Ed25519
//   - Canonical form: both use canonicalizeRecord (JCS bytes)
//   - Chain-hash: both include the per-event SHA-256 chain hash
//   - Merkle-root: NEITHER includes it as a fair cost baseline is per-event work
//     For the batched configuration we DO include the Merkle root + epoch sign cost
//     amortized across the epoch, since that IS the batched pipeline.
//
// Difference under test:
//   - single: nodeSign(Ed25519) on the canonical bytes for every record
//   - batched: append leaf hash; at epoch boundary, compute Merkle root and nodeSign
//     the root once (epoch=100, matching AFR Full).
//
// Reports per-round MEAN per-event microseconds (total wallclock / N) for both modes.
// This is the honest apples-to-apples number: it counts every byte of work performed,
// including epoch-boundary Merkle+sign cost in the batched mode.
//
// Run: node bench/signer-benchmark-samestack-ab.mjs [--n=100000] [--rounds=30] [--epoch=100]

import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  canonicalizeRecord,
} from "../dist/attestation/signer.js";

const argN = process.argv.find((a) => a.startsWith("--n="));
const argR = process.argv.find((a) => a.startsWith("--rounds="));
const argE = process.argv.find((a) => a.startsWith("--epoch="));
const N = argN ? parseInt(argN.slice(4), 10) : 100000;
const ROUNDS = argR ? parseInt(argR.slice(9), 10) : 30;
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

// Single-sign Ed25519, same Node/OpenSSL/JCS stack.
// Per event: canonicalize, sign, chain-hash. No batching.
function runSingleRound(n, privateKey) {
  let prevHash = "genesis";
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const canonical = canonicalizeRecord(rec);
    const sig = nodeSign(null, Buffer.from(canonical, "utf8"), privateKey);
    const chainHash = createHash("sha256").update(canonical + prevHash).digest("hex");
    prevHash = chainHash;
    // consume sig to prevent DCE
    if (sig.length < 0) console.log("dce");
  }
  const t1 = performance.now();
  const totalMs = t1 - t0;
  const meanUs = (totalMs * 1000) / n;
  return { totalMs, meanUs };
}

// Batched Ed25519, same Node/OpenSSL/JCS stack.
// Per event: canonicalize, chain-hash, append leaf.
// At epoch boundary: build Merkle root, sign root once with Ed25519.
// Total wallclock / N gives the amortized per-event cost.
function runBatchedRound(n, epochSize, privateKey) {
  let prevHash = "genesis";
  let currentEpochLeaves = [];
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeAuditRecord(i, prevHash);
    const canonical = canonicalizeRecord(rec);
    const chainHash = createHash("sha256").update(canonical + prevHash).digest("hex");
    prevHash = chainHash;
    currentEpochLeaves.push(chainHash);
    if (currentEpochLeaves.length >= epochSize) {
      const root = merkleRoot(currentEpochLeaves);
      const sig = nodeSign(null, root, privateKey);
      if (sig.length < 0) console.log("dce");
      currentEpochLeaves = [];
    }
  }
  // Flush any final partial epoch to be fair (though N is divisible by epoch).
  if (currentEpochLeaves.length > 0) {
    const root = merkleRoot(currentEpochLeaves);
    const sig = nodeSign(null, root, privateKey);
    if (sig.length < 0) console.log("dce");
  }
  const t1 = performance.now();
  const totalMs = t1 - t0;
  const meanUs = (totalMs * 1000) / n;
  return { totalMs, meanUs };
}

async function main() {
  console.log(`Same-stack A/B: batched vs. single Ed25519`);
  console.log(`Node ${process.version}, arch ${process.arch}, platform ${process.platform}`);
  console.log(`Config: N=${N} events/round, ROUNDS=${ROUNDS}, epoch=${EPOCH_SIZE}`);
  console.log(`Stack: Node.js/V8, node:crypto OpenSSL Ed25519, canonicalizeRecord (JCS bytes)`);
  console.log(`Metric: per-round mean-per-event microseconds (total wallclock / N)`);
  console.log("");

  const { privateKey } = generateKeyPairSync("ed25519");

  // Warmup — each function once
  runBatchedRound(Math.min(5000, Math.floor(N / 20)), EPOCH_SIZE, privateKey);
  runSingleRound(Math.min(5000, Math.floor(N / 20)), privateKey);

  const batchedMeansUs = [];
  const singleMeansUs = [];

  // Interleave rounds so any cross-round drift affects both modes symmetrically.
  for (let r = 0; r < ROUNDS; r++) {
    const bRes = runBatchedRound(N, EPOCH_SIZE, privateKey);
    const sRes = runSingleRound(N, privateKey);
    batchedMeansUs.push(bRes.meanUs);
    singleMeansUs.push(sRes.meanUs);
    console.log(`round ${(r + 1).toString().padStart(2, " ")}: batched=${bRes.meanUs.toFixed(3)}µs  single=${sRes.meanUs.toFixed(3)}µs  ratio=${(sRes.meanUs / bRes.meanUs).toFixed(2)}×`);
  }

  const mean = (a) => a.reduce((s, v) => s + v, 0) / a.length;
  const batchedMean = mean(batchedMeansUs);
  const singleMean = mean(singleMeansUs);
  const ratio = singleMean / batchedMean;

  console.log("");
  console.log(`### Aggregate (n=${ROUNDS} rounds each side)`);
  console.log(`batched mean-per-event: ${batchedMean.toFixed(3)} µs`);
  console.log(`single  mean-per-event: ${singleMean.toFixed(3)} µs`);
  console.log(`point-estimate batching ratio: ${ratio.toFixed(3)}×`);

  // Emit machine-readable JSON tail
  console.log("");
  console.log("=== BEGIN JSON ===");
  console.log(JSON.stringify({
    n_per_round: N,
    rounds: ROUNDS,
    epoch: EPOCH_SIZE,
    node_version: process.version,
    arch: process.arch,
    platform: process.platform,
    batched_means_us: batchedMeansUs,
    single_means_us: singleMeansUs,
    batched_mean_us: batchedMean,
    single_mean_us: singleMean,
    batching_ratio_point: ratio,
  }, null, 2));
  console.log("=== END JSON ===");
}

main().catch((e) => { console.error(e); process.exit(1); });

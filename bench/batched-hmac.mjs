// Batched HMAC (Merkle-style) — wrap-mode analog of batched Ed25519.
// Per-event: canonicalize + chain hash + append leaf. Epoch boundary: Merkle root + HMAC.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { canonicalizeRecord } from "../dist/attestation/signer.js";

const N = 100000;
const ROUNDS = 5;
const EPOCH_SIZES = [50, 100, 500, 1000];

function makeRecord(i, prevHash) {
  return { id: `rec-${i.toString().padStart(8, "0")}`, timestamp: new Date(1735000000000 + i * 1000).toISOString(), method: "tools/call", toolName: "example_tool", namespace: "example.namespace", upstream: "example-server", principal: "user@example", durationMs: 42, success: true, errorCode: undefined, previousHash: prevHash };
}

function merkleRoot(leaves) {
  if (leaves.length === 0) return Buffer.alloc(32);
  let level = leaves.map((l) => Buffer.from(l, "hex"));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i]; const r = i+1 < level.length ? level[i+1] : l;
      next.push(createHash("sha256").update(Buffer.concat([l, r])).digest());
    }
    level = next;
  }
  return level[0];
}

async function bench(n, epochSize) {
  const secret = randomBytes(32);
  const latencies = new Float64Array(n);
  let prev = "genesis", leaves = [], epochSigns = 0, epochCost = 0;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(i, prev);
    const s = performance.now();
    const canonical = canonicalizeRecord(rec);
    const chainHash = createHash("sha256").update(canonical + prev).digest("hex");
    prev = chainHash;
    leaves.push(chainHash);
    latencies[i] = performance.now() - s;
    if (leaves.length >= epochSize) {
      const es = performance.now();
      const root = merkleRoot(leaves);
      createHmac("sha256", secret).update(root).digest();
      epochCost += performance.now() - es;
      epochSigns++;
      leaves = [];
    }
  }
  const wall = performance.now() - t0;
  const sorted = [...latencies].sort((a,b)=>a-b);
  const p50 = sorted[Math.floor(n*0.5)] * 1000;
  const amortized = ((latencies.reduce((s,v)=>s+v,0) / n) * 1000) + (epochCost / n * 1000);
  return { p50, amortized, throughput: (n/wall)*1000, epochSigns };
}

console.log(`Batched HMAC (wrap-mode analog), N=${N}, rounds=${ROUNDS}`);
for (const e of EPOCH_SIZES) {
  const rs = [];
  await bench(1000, e); // warmup
  for (let r = 0; r < ROUNDS; r++) rs.push(await bench(N, e));
  const meanP50 = rs.reduce((s,r)=>s+r.p50,0)/ROUNDS;
  const meanAmort = rs.reduce((s,r)=>s+r.amortized,0)/ROUNDS;
  const meanTP = rs.reduce((s,r)=>s+r.throughput,0)/ROUNDS;
  console.log(`  epoch=${e}:  p50=${meanP50.toFixed(2)}µs  amortized=${meanAmort.toFixed(2)}µs  throughput=${meanTP.toFixed(0)} evt/s`);
}

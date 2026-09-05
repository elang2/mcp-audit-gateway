// Tamper-detection benchmark for mcp-audit-gateway.
// Generates a signed hash-chained audit log, then applies four attack classes:
//   1. EDIT — modify a field value in a middle record
//   2. DELETE — drop a middle record entirely
//   3. REORDER — swap two records
//   4. FORK — duplicate a record and insert a divergent branch
// Reports detection rate per attack class.
// Compared to AFR's reported 100% detection on the same four classes.

import { createHash, generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { performance } from "node:perf_hooks";
import { HmacSigner, canonicalizeRecord } from "../dist/attestation/signer.js";
import { randomBytes } from "node:crypto";

const CHAIN_LENGTH = 100;
const TRIALS_PER_ATTACK = 30;

function makeRecord(i, prevHash) {
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
    previousHash: prevHash,
  };
}

async function buildChain(signer, n) {
  const chain = [];
  let prev = "genesis";
  for (let i = 0; i < n; i++) {
    const rec = makeRecord(i, prev);
    const sig = await signer.sign(rec);
    const withSig = { ...rec, attestation: sig };
    const chainHash = createHash("sha256").update(JSON.stringify(withSig)).digest("hex");
    prev = chainHash;
    chain.push({ record: withSig, chainHash });
  }
  return chain;
}

async function verifyChain(chain, signer) {
  let prev = "genesis";
  for (let i = 0; i < chain.length; i++) {
    const { record, chainHash } = chain[i];
    if (record.previousHash !== prev) return { tampered: true, at: i, reason: "chain-break" };
    // Verify signature
    const recordWithoutAttestation = { ...record };
    delete recordWithoutAttestation.attestation;
    const sigValid = await signer.verify(recordWithoutAttestation, record.attestation);
    if (!sigValid) return { tampered: true, at: i, reason: "bad-signature" };
    // Verify chain hash
    const expected = createHash("sha256").update(JSON.stringify(record)).digest("hex");
    if (expected !== chainHash) return { tampered: true, at: i, reason: "bad-chain-hash" };
    prev = chainHash;
  }
  return { tampered: false };
}

async function attackEdit(chain) {
  const attacked = JSON.parse(JSON.stringify(chain));
  const idx = Math.floor(chain.length / 2);
  attacked[idx].record.toolName = "TAMPERED";
  return attacked;
}

async function attackDelete(chain) {
  const attacked = JSON.parse(JSON.stringify(chain));
  attacked.splice(Math.floor(chain.length / 2), 1);
  return attacked;
}

async function attackReorder(chain) {
  const attacked = JSON.parse(JSON.stringify(chain));
  const i = Math.floor(chain.length / 3);
  const j = Math.floor(2 * chain.length / 3);
  const tmp = attacked[i];
  attacked[i] = attacked[j];
  attacked[j] = tmp;
  return attacked;
}

async function attackFork(chain) {
  const attacked = JSON.parse(JSON.stringify(chain));
  const idx = Math.floor(chain.length / 2);
  // Duplicate record at idx; both claim the same previousHash but diverge
  const fork = JSON.parse(JSON.stringify(attacked[idx]));
  fork.record.toolName = "FORK-BRANCH";
  attacked.splice(idx + 1, 0, fork);
  return attacked;
}

async function runAttackClass(name, attackFn, signer, cleanChain) {
  let detected = 0;
  for (let trial = 0; trial < TRIALS_PER_ATTACK; trial++) {
    const tampered = await attackFn(cleanChain);
    const result = await verifyChain(tampered, signer);
    if (result.tampered) detected++;
  }
  const rate = (detected / TRIALS_PER_ATTACK) * 100;
  console.log(`  ${name}: ${detected}/${TRIALS_PER_ATTACK} detected (${rate.toFixed(1)}%)`);
  return { attack: name, detected, total: TRIALS_PER_ATTACK, rate };
}

async function main() {
  console.log(`Tamper-detection benchmark for mcp-audit-gateway HMAC wrap mode`);
  console.log(`Chain length: ${CHAIN_LENGTH} records, ${TRIALS_PER_ATTACK} trials per attack class\n`);

  const secret = randomBytes(32).toString("hex");
  const signer = new HmacSigner(secret);
  const cleanChain = await buildChain(signer, CHAIN_LENGTH);

  // Sanity: clean chain must verify cleanly
  const cleanResult = await verifyChain(cleanChain, signer);
  console.log(`Clean chain sanity: ${cleanResult.tampered ? "FAIL (bug!)" : "PASS"}\n`);
  if (cleanResult.tampered) return;

  console.log(`Attack detection rates:`);
  const results = [];
  results.push(await runAttackClass("Edit  (modify field)", attackEdit, signer, cleanChain));
  results.push(await runAttackClass("Delete(drop record)", attackDelete, signer, cleanChain));
  results.push(await runAttackClass("Reorder(swap two)", attackReorder, signer, cleanChain));
  results.push(await runAttackClass("Fork  (duplicate)", attackFork, signer, cleanChain));

  const overall = results.reduce((s, r) => s + r.rate, 0) / results.length;
  console.log(`\nOverall detection rate across 4 attack classes: ${overall.toFixed(1)}%`);
  console.log(`Compare to AFR (Bindschaedler et al., binds.ch): 100% on all 4 classes`);
}

main().catch((e) => { console.error(e); process.exit(1); });

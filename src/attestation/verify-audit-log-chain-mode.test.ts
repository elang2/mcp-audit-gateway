// Covers the coverage gap raised against v0.7.8 on
// modelcontextprotocol/modelcontextprotocol#3004: the four tamper cases in
// chain.test.ts exercise the records-based verifyChain(records), but the CLI
// (cli.ts) calls verifyAuditLog(path, signer, { verifyChain: true }) which
// takes an octets-based branch (hashLine on the raw JSONL). These tests pin
// tamper rejection through that shipping path.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { HmacSigner } from "./signer.js";
import { AuditLog } from "./audit-log.js";
import { verifyAuditLog } from "./verify.js";

const TEST_LOG = "/tmp/test-verify-audit-chain-mode.jsonl";
const SECRET = "c".repeat(64);

async function buildLog(signer: HmacSigner, count: number): Promise<void> {
  const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
  await log.init();
  for (let i = 0; i < count; i++) {
    await log.record("tools/call", {
      toolName: `test/tool_${i}`,
      namespace: "test",
      upstream: "test-server",
      principal: "agent:bot",
      durationMs: 10 + i,
      success: true,
    });
  }
}

async function readLines(): Promise<string[]> {
  const content = await readFile(TEST_LOG, "utf-8");
  return content.trimEnd().split("\n");
}

describe("verifyAuditLog with { verifyChain: true } (shipping CLI path)", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });
  afterEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });

  it("clean multi-record log passes chain-mode verification", async () => {
    await buildLog(signer, 4);

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(4);
    expect(result.valid).toBe(4);
    expect(result.invalid).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it("detects content tamper of an intermediate record", async () => {
    await buildLog(signer, 4);
    const lines = await readLines();
    // Tamper record 2 (0-indexed): flip success:true → success:false. Bytes change,
    // so signature no longer matches AND the octets-based chain hash changes,
    // which the next record's previousHash won't match.
    lines[1] = lines[1].replace('"success":true', '"success":false');
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(4);
    // Line 2 fails signature. Line 3 fails chain-hash-mismatch (its previousHash
    // was computed against the pre-tamper line 2 bytes).
    expect(result.invalid).toBe(2);
    expect(result.valid).toBe(2);
    expect(result.valid + result.invalid).toBe(result.total);
    const reasons = result.errors.map((e) => e.reason);
    expect(reasons).toContain("signature mismatch");
    expect(reasons).toContain("chain hash mismatch");
  });

  it("detects a deleted intermediate record", async () => {
    await buildLog(signer, 4);
    const lines = await readLines();
    // Remove record 2 (0-indexed). Records 3 and 4 still have their original
    // previousHash which pointed at record 2. The record now at position 2 is
    // the original record 3, whose previousHash is stale.
    lines.splice(1, 1);
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(3);
    // The record now at position 2 was formerly at position 3; its stored
    // previousHash points at the deleted record, not the record actually before
    // it in the file. Position 4 re-syncs because its stored previousHash still
    // matches the (unchanged) bytes of the line now preceding it.
    const chainErrors = result.errors.filter((e) => e.reason === "chain hash mismatch");
    expect(chainErrors).toHaveLength(1);
  });

  it("detects reordered records", async () => {
    await buildLog(signer, 4);
    const lines = await readLines();
    // Swap records 2 and 3 (0-indexed). Their previousHash fields now point at
    // the wrong previous line in the reordered sequence.
    [lines[1], lines[2]] = [lines[2], lines[1]];
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(4);
    // Swap propagates: position 1 stores previousHash of the old position 1 record,
    // but rolling state after position 0 is hashLine(A) — mismatch. Position 2
    // stores previousHash of A, rolling state is hashLine(C) — mismatch. Position 3
    // stores previousHash of C, rolling state is hashLine(B) — mismatch.
    const chainErrors = result.errors.filter((e) => e.reason === "chain hash mismatch");
    expect(chainErrors).toHaveLength(3);
  });
});

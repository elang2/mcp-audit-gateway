// Covers the coverage gap raised against v0.7.8 on
// modelcontextprotocol/modelcontextprotocol#3004: the three tamper cases in
// chain.test.ts (delete, reorder, insert) exercise the records-based
// verifyChain(records), but the CLI (cli.ts) calls verifyAuditLog(path,
// signer, { verifyChain: true }) which takes an octets-based branch (hashLine
// on the raw JSONL). These tests pin tamper rejection through that shipping
// path and additionally cover content-tamper of an intermediate record, which
// chain.test.ts does not exercise on either path.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
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

  it("detects an inserted record", async () => {
    await buildLog(signer, 4);
    const lines = await readLines();
    // Insert a fabricated line between positions 0 and 1. The inserted line
    // was not produced by the signer, so its own signature check fails. The
    // inserted record's own previousHash claim ("genesis") disagrees with the
    // rolling state (hashLine of the real first record), and the record
    // immediately following it stores a previousHash pointing at the
    // pre-insertion prior line rather than at the fabricated one. Records
    // further downstream re-sync because their stored previousHash still
    // matches the (unchanged) bytes of the line now preceding them: after
    // the immediate-successor mismatch, the rolling state at verify.ts:99
    // becomes hashLine(original_L1_line), which is exactly what original_L2's
    // stored previousHash points at. The failures pin two distinct chain-hash
    // mismatches (fabricated own, immediate successor) plus one signature
    // mismatch on the fabricated record, so three error entries over two
    // invalid records.
    //
    // The re-sync reasoning above holds only because the fabricated line
    // carries an attestation field and therefore reaches the chain block.
    // verifyAuditLog `continue`s the loop on unparseable JSON (verify.ts:52)
    // and on a missing attestation (verify.ts:60) WITHOUT advancing the
    // rolling hash — it returns only after the loop, at verify.ts:103 — so a
    // fabricated line omitting `attestation` yields one "missing attestation"
    // error and leaves the chain intact for every later record. That case is
    // asserted by "leaves the chain intact downstream of an inserted record
    // with no attestation" below.
    const fabricated = JSON.stringify({
      id: "fake-inserted-id",
      timestamp: "2026-09-10T00:00:00.000Z",
      method: "tools/call",
      toolName: "test/malicious_tool",
      durationMs: 1,
      success: true,
      previousHash: "genesis",
      attestation: "AA".repeat(32),
    });
    lines.splice(1, 0, fabricated);
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(5);
    expect(result.invalid).toBe(2);
    expect(result.valid).toBe(3);
    const chainErrors = result.errors.filter((e) => e.reason === "chain hash mismatch");
    const sigErrors = result.errors.filter((e) => e.reason === "signature mismatch");
    expect(chainErrors).toHaveLength(2);
    expect(sigErrors).toHaveLength(1);
    // Pin both chain-mismatch failure modes by line number so a future
    // regression that suppresses either one is caught.
    expect(result.errors.find((e) => e.line === 2 && e.reason === "signature mismatch")).toBeDefined();
    expect(result.errors.find((e) => e.line === 2 && e.reason === "chain hash mismatch")).toBeDefined();
    expect(result.errors.find((e) => e.line === 3 && e.reason === "chain hash mismatch")).toBeDefined();
  });

  it("marks two records invalid for a mid-sequence insertion at any tail length", async () => {
    // The two-invalid-records count is invariant in tail length because the
    // rolling hash advances past the immediate successor unchanged, so every
    // later record re-syncs. Asserted at three lengths rather than argued.
    for (const n of [4, 20, 60]) {
      await unlink(TEST_LOG).catch(() => {});
      await buildLog(signer, n);
      const lines = await readLines();
      lines.splice(1, 0, JSON.stringify({
        id: "fake-inserted-id",
        timestamp: "2026-09-10T00:00:00.000Z",
        method: "tools/call",
        toolName: "test/malicious_tool",
        durationMs: 1,
        success: true,
        previousHash: "genesis",
        attestation: "AA".repeat(32),
      }));
      await writeFile(TEST_LOG, lines.join("\n") + "\n");

      const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
      expect(result.total).toBe(n + 1);
      expect(result.invalid).toBe(2);
      expect(result.errors).toHaveLength(3);
    }
  });

  it("marks one record invalid for an insertion at the tail", async () => {
    // A tail insertion has no successor to desync, so the two-invalid count
    // above is specific to mid-sequence insertion. Pinned so the stronger
    // claim is never over-generalised.
    await buildLog(signer, 20);
    const lines = await readLines();
    lines.push(JSON.stringify({
      id: "fake-tail-id",
      timestamp: "2026-09-10T00:00:00.000Z",
      method: "tools/call",
      toolName: "test/malicious_tool",
      durationMs: 1,
      success: true,
      previousHash: "genesis",
      attestation: "AA".repeat(32),
    }));
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(21);
    expect(result.invalid).toBe(1);
    expect(result.errors).toHaveLength(2);
    expect(result.errors.map((e) => e.reason).sort()).toEqual(
      ["chain hash mismatch", "signature mismatch"],
    );
  });

  it("leaves the chain intact downstream of an inserted record with no attestation", async () => {
    // A design property of chain mode rather than a coverage gap. The missing-
    // attestation branch continues before the rolling hash advances, so an
    // unsigned inserted record is flagged for its missing attestation and
    // every later record still verifies against an undisturbed rolling state.
    // The record IS detected, but not as a chain break, and a reader counting
    // chain-hash mismatches would see none.
    await buildLog(signer, 20);
    const lines = await readLines();
    lines.splice(1, 0, JSON.stringify({
      id: "fake-unsigned-id",
      timestamp: "2026-09-10T00:00:00.000Z",
      method: "tools/call",
      toolName: "test/malicious_tool",
      durationMs: 1,
      success: true,
      previousHash: "genesis",
    }));
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(21);
    expect(result.invalid).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].reason).toBe("missing attestation");
    expect(result.errors[0].line).toBe(2);
    expect(result.errors.filter((e) => e.reason === "chain hash mismatch")).toHaveLength(0);
  });

  it("catches a tail insert carrying a correct previousHash by signature alone", async () => {
    // The other cases give the fabricated record previousHash "genesis", which
    // chain mode rejects on its own. But hashLine is a bare SHA-256 over the
    // stored line and takes no secret, so an attacker can compute the correct
    // previousHash for any position. Appended at the tail with a correct link,
    // the chain check PASSES and only the signature check fails: one error, not
    // two. The blind spot is positional, not general — the same correctly-linked
    // insert placed MID-sequence still desyncs its successor and yields two
    // errors with one chain-hash mismatch (measured at positions 1 and 10). Only
    // at the tail is there no successor to desync. Note also that a tail insert
    // with a correct link AND a valid signature would be silent here; the
    // signature is the backstop only against forgers without the key.
    await buildLog(signer, 20);
    const lines = await readLines();
    const correctPrev = createHash("sha256").update(lines[lines.length - 1]).digest("hex");
    lines.push(JSON.stringify({
      id: "fake-linked-id",
      timestamp: "2026-09-10T00:00:00.000Z",
      method: "tools/call",
      toolName: "test/malicious_tool",
      durationMs: 1,
      success: true,
      previousHash: correctPrev,
      attestation: "AA".repeat(32),
    }));
    await writeFile(TEST_LOG, lines.join("\n") + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(21);
    expect(result.invalid).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].reason).toBe("signature mismatch");
    expect(result.errors.filter((e) => e.reason === "chain hash mismatch")).toHaveLength(0);
  });
});

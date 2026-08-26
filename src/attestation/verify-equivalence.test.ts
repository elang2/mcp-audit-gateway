import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { unlink, readFile } from "node:fs/promises";
import { HmacSigner } from "./signer.js";
import { AuditLog } from "./audit-log.js";
import { verifyChain, verifyChainLines } from "./verify.js";
import type { AuditRecord, ChainRecord } from "../types.js";

const TEST_LOG = "/tmp/test-verify-equivalence-audit.jsonl";
const SECRET = "d".repeat(64);

const hashLine = (line: string): string =>
  createHash("sha256").update(line).digest("hex");

async function readLines(path: string): Promise<string[]> {
  const content = await readFile(path, "utf-8");
  return content.split("\n").filter((l) => l.trim().length > 0);
}

describe("verifyChain vs verifyChainLines boundary", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });
  afterEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });

  // Equivalence: for records the current writer actually emits, both paths must
  // agree. This converts the JSDoc condition on verifyChain ("correct only when
  // insertion-order is preserved") into an enforced invariant on the code path
  // producer-conforming records travel.
  it("verifyChain and verifyChainLines agree on writer-emitted records", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a", namespace: "test", upstream: "test-server",
      principal: "agent:bot", durationMs: 100, success: true,
    });
    await log.record("tools/call", {
      toolName: "test/tool_b", namespace: "test", upstream: "test-server",
      principal: "agent:bot", durationMs: 50, success: true,
    });
    await log.record("tools/call", {
      toolName: "test/tool_c", namespace: "test", upstream: "test-server",
      principal: "agent:bot", durationMs: 75, success: true,
    });

    const lines = await readLines(TEST_LOG);
    const records = lines.map((l) => JSON.parse(l) as ChainRecord);

    const linesResult = await verifyChainLines(lines);
    const chainResult = await verifyChain(records);

    expect(linesResult.valid).toBe(true);
    expect(chainResult.valid).toBe(true);
    expect(linesResult.errors).toHaveLength(0);
    expect(chainResult.errors).toHaveLength(0);
    expect(linesResult.total).toBe(chainResult.total);
  });

  // Divergence: when a foreign or future record shape arrives with an
  // integer-like top-level key (e.g. "1", "2"), ECMA-262 §10.1.11.1
  // (OrdinaryOwnPropertyKeys) requires integer-indexed properties to
  // enumerate before string keys — so JSON.stringify(JSON.parse(line))
  // (which hashRecord uses) produces different bytes than the stored
  // line. verifyChainLines hashes the stored octets and remains correct;
  // verifyChain re-serializes and reports a chain mismatch.
  //
  // NOTE: the current writer's TypeScript interface (AuditRecord) has no
  // place for integer-like keys — aiInvocation is a closed shape and there
  // is no free-form extensions object. This fixture therefore represents
  // a foreign shape received from a different implementation, not a
  // record this codebase would emit; it is hand-crafted as raw JSONL
  // bytes and bypasses the writer entirely, so it cannot silently turn
  // into a producer-bug test if the writer's schema changes. The sibling
  // equivalence test above is the regression guard for writer output.
  it("verifyChain and verifyChainLines diverge on foreign records with integer-like top-level keys", async () => {
    // Constructed manually so the wire order of "1" / "2" precedes the reorder
    // that JSON.parse would apply.
    const rec1Line =
      '{"id":"rec-foreign-1","timestamp":"2026-08-25T00:00:00Z","method":"tools/call",' +
      '"2":"second-value","toolName":"test/foreign","1":"first-value",' +
      '"durationMs":1,"success":true,"previousHash":"genesis"}';

    // Sanity check: JSON.parse must actually reorder — else this fixture
    // proves nothing and the test would be zero-coverage in disguise.
    const parsedKeys = Object.keys(JSON.parse(rec1Line));
    expect(parsedKeys[0]).toBe("1");
    expect(parsedKeys[1]).toBe("2");

    const rec1Hash = hashLine(rec1Line);
    const rec2: AuditRecord = {
      id: "rec-foreign-2",
      timestamp: "2026-08-25T00:01:00Z",
      method: "tools/call",
      toolName: "test/foreign_next",
      durationMs: 2,
      success: true,
      previousHash: rec1Hash,
    };
    const rec2Line = JSON.stringify(rec2);

    const lines = [rec1Line, rec2Line];
    const records = lines.map((l) => JSON.parse(l) as ChainRecord);

    const linesResult = await verifyChainLines(lines);
    expect(linesResult.valid).toBe(true);
    expect(linesResult.errors).toHaveLength(0);

    const chainResult = await verifyChain(records);
    expect(chainResult.valid).toBe(false);
    expect(chainResult.errors.length).toBeGreaterThan(0);
    // Property-level assertion: test that at least one error mentions
    // previousHash (the divergence's semantic signature) rather than
    // hard-coding the current error string. Robust to future rewording
    // of verify.ts's error messages.
    expect(chainResult.errors.some((e) => e.reason.includes("previousHash"))).toBe(true);
  });
});

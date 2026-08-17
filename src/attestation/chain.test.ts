import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { unlink, readFile } from "node:fs/promises";
import { HmacSigner } from "./signer.js";
import { AuditLog, hashRecord } from "./audit-log.js";
import { verifyChain } from "./verify.js";
import type { AuditRecord } from "../types.js";

const TEST_LOG = "/tmp/test-chain-audit.jsonl";
const SECRET = "c".repeat(64);

async function readRecords(path: string): Promise<AuditRecord[]> {
  const content = await readFile(path, "utf-8");
  return content
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}

describe("hash chain integrity", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => {
    try {
      await unlink(TEST_LOG);
    } catch {}
  });

  afterEach(async () => {
    try {
      await unlink(TEST_LOG);
    } catch {}
  });

  it("valid chain passes verification", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a",
      namespace: "test",
      upstream: "test-server",
      principal: "agent:bot",
      durationMs: 100,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_b",
      namespace: "test",
      upstream: "test-server",
      principal: "agent:bot",
      durationMs: 50,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_c",
      namespace: "test",
      upstream: "test-server",
      principal: "agent:bot",
      durationMs: 75,
      success: true,
    });

    const records = await readRecords(TEST_LOG);
    const result = await verifyChain(records);

    expect(result.valid).toBe(true);
    expect(result.total).toBe(3);
    expect(result.errors).toHaveLength(0);

    // Verify first record has genesis
    expect(records[0].previousHash).toBe("genesis");

    // Verify second record references hash of first
    expect(records[1].previousHash).toBe(hashRecord(records[0]));

    // Verify third record references hash of second
    expect(records[2].previousHash).toBe(hashRecord(records[1]));
  });

  it("detects deleted record", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a",
      durationMs: 100,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_b",
      durationMs: 50,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_c",
      durationMs: 75,
      success: true,
    });

    const records = await readRecords(TEST_LOG);
    // Remove the middle record
    const tampered = [records[0], records[2]];

    const result = await verifyChain(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].reason).toBe(
      "previousHash does not match hash of prior record",
    );
  });

  it("detects reordered records", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a",
      durationMs: 100,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_b",
      durationMs: 50,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_c",
      durationMs: 75,
      success: true,
    });

    const records = await readRecords(TEST_LOG);
    // Swap the second and third records
    const reordered = [records[0], records[2], records[1]];

    const result = await verifyChain(reordered);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].reason).toBe(
      "previousHash does not match hash of prior record",
    );
  });

  it("detects inserted record (previousHash won't match)", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a",
      durationMs: 100,
      success: true,
    });

    await log.record("tools/call", {
      toolName: "test/tool_b",
      durationMs: 50,
      success: true,
    });

    const records = await readRecords(TEST_LOG);

    // Insert a fake record between the two
    const inserted: AuditRecord = {
      id: "fake-inserted-id",
      timestamp: new Date().toISOString(),
      method: "tools/call",
      toolName: "test/malicious_tool",
      durationMs: 1,
      success: true,
      previousHash: hashRecord(records[0]),
    };

    const tampered = [records[0], inserted, records[1]];

    const result = await verifyChain(tampered);
    expect(result.valid).toBe(false);
    // The record after the inserted one will fail because its previousHash
    // was computed against the original record[0], not the inserted record
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e) => e.reason === "previousHash does not match hash of prior record")).toBe(true);
  });
});

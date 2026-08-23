import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { unlink, writeFile } from "node:fs/promises";
import { AuditLog, hashRecord } from "./audit-log.js";
import { HmacSigner, canonicalizeCheckpoint, canonicalizeChainBreak, canonicalizeValue, computeExtensionsDigest } from "./signer.js";
import { verifyChain, verifyCompleteness } from "./verify.js";
import { createHash } from "node:crypto";
import type { AuditRecord, CheckpointRecord, ChainBreakRecord, ChainRecord } from "../types.js";
import { isCheckpoint, isChainBreak } from "../types.js";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

const TEST_AUDIT_PATH = "/tmp/checkpoint-test-audit.jsonl";
const SECRET = "a".repeat(64);

async function readAllRecords(path: string): Promise<ChainRecord[]> {
  const records: ChainRecord[] = [];
  const rl = createInterface({
    input: createReadStream(path),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    if (line.trim()) records.push(JSON.parse(line));
  }
  return records;
}

describe("Checkpoint Records", () => {
  let auditLog: AuditLog;
  let signer: HmacSigner;

  beforeEach(async () => {
    try { await unlink(TEST_AUDIT_PATH); } catch {}
    try { await unlink(TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json")); } catch {}
    try { await unlink(TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json.tmp")); } catch {}
    signer = new HmacSigner(SECRET);
    auditLog = new AuditLog(TEST_AUDIT_PATH, signer, 100 * 1024 * 1024);
    await auditLog.init();
  });

  afterEach(async () => {
    try { await unlink(TEST_AUDIT_PATH); } catch {}
    try { await unlink(TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json")); } catch {}
    try { await unlink(TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json.tmp")); } catch {}
  });

  it("emits a checkpoint record with correct fields", async () => {
    await auditLog.record("tools/call", {
      toolName: "test_tool",
      namespace: "test",
      upstream: "test-server",
      durationMs: 50,
      success: true,
    });

    const checkpoint = await auditLog.emitCheckpoint();

    expect(checkpoint.type).toBe("checkpoint");
    expect(checkpoint.id).toMatch(/^ckpt_/);
    expect(checkpoint.sequence).toBe(1);
    expect(checkpoint.recordCount).toBe(1);
    expect(checkpoint.previousHash).not.toBe("genesis");
    expect(checkpoint.attestation).toBeDefined();
    expect(checkpoint.parties).toEqual([
      { party: "gateway", role: "witness", scope: ["sequence", "recordCount", "previousHash"] },
    ]);
  });

  it("checkpoint chains correctly with preceding records", async () => {
    await auditLog.record("tools/call", {
      toolName: "tool_a",
      namespace: "ns",
      upstream: "srv",
      durationMs: 10,
      success: true,
    });
    await auditLog.record("tools/call", {
      toolName: "tool_b",
      namespace: "ns",
      upstream: "srv",
      durationMs: 20,
      success: true,
    });
    await auditLog.emitCheckpoint();

    const records = await readAllRecords(TEST_AUDIT_PATH);
    expect(records.length).toBe(3);

    const chainResult = await verifyChain(records);
    expect(chainResult.valid).toBe(true);
    expect(chainResult.errors).toHaveLength(0);
  });

  it("checkpoint signature is verifiable", async () => {
    await auditLog.record("tools/call", {
      toolName: "tool_a",
      namespace: "ns",
      upstream: "srv",
      durationMs: 10,
      success: true,
    });

    const checkpoint = await auditLog.emitCheckpoint();
    const sig = checkpoint.attestation!;
    const toVerify = { ...checkpoint };
    delete toVerify.attestation;
    const valid = await signer.verify(toVerify, sig);
    expect(valid).toBe(true);
  });

  it("auto-emits checkpoint at record interval", async () => {
    auditLog.enableCheckpoints({
      enabled: true,
      intervalRecords: 3,
      intervalSeconds: 9999,
      trigger: "records",
    });

    for (let i = 0; i < 5; i++) {
      await auditLog.record("tools/call", {
        toolName: `tool_${i}`,
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });
    }

    const records = await readAllRecords(TEST_AUDIT_PATH);
    const checkpoints = records.filter(isCheckpoint);
    expect(checkpoints.length).toBe(1);
    expect(checkpoints[0].sequence).toBe(1);
    expect(checkpoints[0].recordCount).toBe(3);
  });

  it("increments sequence across multiple checkpoints", async () => {
    auditLog.enableCheckpoints({
      enabled: true,
      intervalRecords: 2,
      intervalSeconds: 9999,
      trigger: "records",
    });

    for (let i = 0; i < 6; i++) {
      await auditLog.record("tools/call", {
        toolName: `tool_${i}`,
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });
    }

    const records = await readAllRecords(TEST_AUDIT_PATH);
    const checkpoints = records.filter(isCheckpoint);
    expect(checkpoints.length).toBe(3);
    expect(checkpoints[0].sequence).toBe(1);
    expect(checkpoints[1].sequence).toBe(2);
    expect(checkpoints[2].sequence).toBe(3);
  });

  it("full chain including checkpoints verifies correctly", async () => {
    auditLog.enableCheckpoints({
      enabled: true,
      intervalRecords: 2,
      intervalSeconds: 9999,
      trigger: "records",
    });

    for (let i = 0; i < 4; i++) {
      await auditLog.record("tools/call", {
        toolName: `tool_${i}`,
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });
    }

    const records = await readAllRecords(TEST_AUDIT_PATH);
    const chainResult = await verifyChain(records);
    expect(chainResult.valid).toBe(true);
  });

  describe("verifyCompleteness", () => {
    it("detects no truncation when checkpoint is present", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 3; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoint = records.find(isCheckpoint) as CheckpointRecord;

      const result = verifyCompleteness(records, {
        previousHash: checkpoint.previousHash,
        sequence: checkpoint.sequence,
        recordCount: checkpoint.recordCount,
      });

      expect(result.truncated).toBe(false);
    });

    it("detects truncation when checkpoint is missing from chain", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 4; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoints = records.filter(isCheckpoint);
      const lastCheckpoint = checkpoints[checkpoints.length - 1];

      const truncatedRecords = records.slice(0, 2);

      const result = verifyCompleteness(truncatedRecords, {
        previousHash: lastCheckpoint.previousHash,
        sequence: lastCheckpoint.sequence,
        recordCount: lastCheckpoint.recordCount,
      });

      expect(result.truncated).toBe(true);
      expect(result.reason).toContain("not found");
    });

    it("passes when a descendant checkpoint exists", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 6; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoints = records.filter(isCheckpoint);
      const firstCheckpoint = checkpoints[0];

      const result = verifyCompleteness(records, {
        previousHash: firstCheckpoint.previousHash,
        sequence: firstCheckpoint.sequence,
        recordCount: firstCheckpoint.recordCount,
      });

      expect(result.truncated).toBe(false);
    });

    it("validates recordCount against actual preceding records", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 3,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 4; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoint = records.find(isCheckpoint) as CheckpointRecord;

      const result = verifyCompleteness(records, {
        previousHash: checkpoint.previousHash,
        sequence: checkpoint.sequence,
        recordCount: checkpoint.recordCount,
      });

      expect(result.truncated).toBe(false);
      expect(result.recordCountValid).toBe(true);
    });

    it("detects recordCount mismatch from spliced prefix", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 3,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 4; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoint = records.find(isCheckpoint) as CheckpointRecord;

      // Simulate splice: remove one record from prefix but keep checkpoint
      const splicedRecords = [records[0], ...records.slice(2)];

      const result = verifyCompleteness(splicedRecords, {
        previousHash: checkpoint.previousHash,
        sequence: checkpoint.sequence,
        recordCount: checkpoint.recordCount,
      });

      expect(result.recordCountValid).toBe(false);
      expect(result.failureCode).toBe("count_mismatch");
      expect(result.reason).toContain("recordCount mismatch");
    });

    it("detects sequence regression", () => {
      const chain: ChainRecord[] = [
        {
          id: "rec1",
          timestamp: "2026-08-22T20:00:00.000Z",
          method: "tools/call",
          toolName: "t1",
          durationMs: 10,
          success: true,
          previousHash: "genesis",
        } as AuditRecord,
        {
          id: "ckpt_1",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:01.000Z",
          sequence: 3,
          recordCount: 1,
          previousHash: "aaa",
        } as CheckpointRecord,
        {
          id: "ckpt_2",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:02.000Z",
          sequence: 2,
          recordCount: 5,
          previousHash: "bbb",
        } as CheckpointRecord,
      ];

      const result = verifyCompleteness(chain, {
        previousHash: "aaa",
        sequence: 3,
        recordCount: 1,
      });

      expect(result.truncated).toBe(true);
      expect(result.failureCode).toBe("sequence_regression");
      expect(result.reason).toContain("sequence regressed");
    });

    it("returns head_missing failure code", () => {
      const chain: ChainRecord[] = [
        {
          id: "rec1",
          timestamp: "2026-08-22T20:00:00.000Z",
          method: "tools/call",
          toolName: "t1",
          durationMs: 10,
          success: true,
          previousHash: "genesis",
        } as AuditRecord,
      ];

      const result = verifyCompleteness(chain, {
        previousHash: "nonexistent",
        sequence: 5,
        recordCount: 10,
      });

      expect(result.truncated).toBe(true);
      expect(result.failureCode).toBe("head_missing");
    });
  });

  describe("sequence recovery across restarts", () => {
    it("recovers checkpoint sequence from existing log", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 4; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      expect(auditLog.getCheckpointSequence()).toBe(2);

      // Simulate restart: create new AuditLog pointing at same file
      const newLog = new AuditLog(TEST_AUDIT_PATH, signer, 100 * 1024 * 1024);
      await newLog.init();
      newLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      expect(newLog.getCheckpointSequence()).toBe(2);

      // New checkpoint should have sequence 3
      await newLog.record("tools/call", {
        toolName: "tool_restart_1",
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });
      await newLog.record("tools/call", {
        toolName: "tool_restart_2",
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoints = records.filter(isCheckpoint);
      const lastCkpt = checkpoints[checkpoints.length - 1];
      expect(lastCkpt.sequence).toBe(3);
    });
  });

  describe("canonicalization", () => {
    it("produces deterministic canonical form for checkpoints", () => {
      const checkpoint: CheckpointRecord = {
        id: "ckpt_test-001",
        type: "checkpoint",
        timestamp: "2026-08-22T20:00:00.000Z",
        sequence: 5,
        recordCount: 42,
        previousHash: "abc123def456",
      };

      const canonical = canonicalizeCheckpoint(checkpoint);
      const expected = JSON.stringify([
        ["id", "ckpt_test-001"],
        ["type", "checkpoint"],
        ["timestamp", "2026-08-22T20:00:00.000Z"],
        ["sequence", 5],
        ["recordCount", 42],
        ["previousHash", "abc123def456"],
      ]);
      expect(canonical).toBe(expected);
    });

    it("includes parties in canonical form when present", () => {
      const checkpoint: CheckpointRecord = {
        id: "ckpt_test-002",
        type: "checkpoint",
        timestamp: "2026-08-22T20:01:00.000Z",
        sequence: 6,
        recordCount: 50,
        previousHash: "def789abc012",
        parties: [{ party: "gateway", role: "witness", scope: ["sequence", "recordCount", "previousHash"] }],
      };

      const canonical = canonicalizeCheckpoint(checkpoint);
      const parsed = JSON.parse(canonical);
      expect(parsed.length).toBe(7);
      expect(parsed[6][0]).toBe("parties");
    });
  });

  describe("canonicalizeValue", () => {
    it("recursively sorts object keys into tagged tuple-arrays", () => {
      const result = canonicalizeValue({ z: 1, a: { y: 2, b: 3 } });
      expect(result).toEqual(["M", [["a", ["M", [["b", 3], ["y", 2]]]], ["z", 1]]]);
    });

    it("preserves array order with type tag", () => {
      const result = canonicalizeValue([3, 1, 2]);
      expect(result).toEqual(["L", [3, 1, 2]]);
    });

    it("produces distinct forms for object vs array-of-pairs (injectivity)", () => {
      const objDigest = computeExtensionsDigest({ a: 1 });
      // This is an object containing a key "items" whose value is an array of pairs
      const arrDigest = computeExtensionsDigest({ items: [["a", 1]] });
      expect(objDigest).not.toBe(arrDigest);
    });

    it("throws on floats", () => {
      expect(() => canonicalizeValue(0.1)).toThrow("unsafe number");
    });

    it("throws on unsafe integers", () => {
      expect(() => canonicalizeValue(2 ** 53)).toThrow("unsafe number");
    });

    it("accepts safe integers", () => {
      expect(canonicalizeValue(42)).toBe(42);
      expect(canonicalizeValue(-1000)).toBe(-1000);
    });

    it("passes strings and booleans through", () => {
      expect(canonicalizeValue("hello")).toBe("hello");
      expect(canonicalizeValue(true)).toBe(true);
    });

    it("treats null and undefined as null", () => {
      expect(canonicalizeValue(null)).toBe(null);
      expect(canonicalizeValue(undefined)).toBe(null);
    });

    it("drops undefined keys (matches JSON.stringify)", () => {
      const result = canonicalizeValue({ a: 1, b: undefined, c: 3 });
      expect(result).toEqual(["M", [["a", 1], ["c", 3]]]);
    });

    it("sorts astral-plane keys by UTF-16 code-unit order", () => {
      // U+10000 has surrogate pair D800 DC00 (first code unit 0xD800 = 55296)
      // U+FF61 has code unit 0xFF61 = 65377
      // UTF-16 code-unit order: U+10000 sorts BEFORE U+FF61
      const input: Record<string, unknown> = {};
      input["｡"] = 1;
      input["\u{10000}"] = 2;
      const result = canonicalizeValue(input);
      const [tag, pairs] = result as [string, [string, unknown][]];
      expect(tag).toBe("M");
      expect(pairs[0][0]).toBe("\u{10000}");
      expect(pairs[1][0]).toBe("｡");
    });

    it("throws on lone surrogate in string value", () => {
      expect(() => canonicalizeValue(String.fromCharCode(0xD800))).toThrow("unpaired surrogate");
    });

    it("throws on lone surrogate in object key", () => {
      const obj: Record<string, unknown> = {};
      obj[String.fromCharCode(0xD800)] = 1;
      expect(() => canonicalizeValue(obj)).toThrow("unpaired surrogate");
    });

    it("produces same digest for different insertion order", () => {
      const d1 = computeExtensionsDigest({ z: 1, a: { y: 2, b: 3 } });
      const d2 = computeExtensionsDigest({ a: { b: 3, y: 2 }, z: 1 });
      expect(d1).toBe(d2);
    });
  });

  describe("chain_break record", () => {
    it("produces deterministic canonical form", () => {
      const record: ChainBreakRecord = {
        id: "break_test-001",
        type: "chain_break",
        timestamp: "2026-08-22T23:00:00.000Z",
        reason: "state_file_corrupt",
        priorHead: "abc123",
        priorSequence: 5,
        priorRecordCount: 100,
      };

      const canonical = canonicalizeChainBreak(record);
      const parsed = JSON.parse(canonical);
      expect(parsed[0]).toEqual(["id", "break_test-001"]);
      expect(parsed[1]).toEqual(["type", "chain_break"]);
      expect(parsed[2]).toEqual(["timestamp", "2026-08-22T23:00:00.000Z"]);
      expect(parsed[3]).toEqual(["reason", "state_file_corrupt"]);
      expect(parsed[4]).toEqual(["priorHead", "abc123"]);
      expect(parsed[5]).toEqual(["priorSequence", 5]);
      expect(parsed[6]).toEqual(["priorRecordCount", 100]);
    });

    it("emits chain_break on forceNewChain", async () => {
      await auditLog.record("tools/call", {
        toolName: "t1",
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });

      const breakRecord = await auditLog.forceNewChain("operator_override");
      expect(breakRecord.type).toBe("chain_break");
      expect(breakRecord.reason).toBe("operator_override");
      expect(breakRecord.priorHead).toBeDefined();
      expect(breakRecord.attestation).toBeDefined();
    });

    it("resets chain state after chain_break", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 2,
        intervalSeconds: 9999,
        trigger: "records",
      });

      await auditLog.record("tools/call", {
        toolName: "t1",
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });
      await auditLog.record("tools/call", {
        toolName: "t2",
        namespace: "ns",
        upstream: "srv",
        durationMs: 10,
        success: true,
      });

      expect(auditLog.getCheckpointSequence()).toBe(1);

      await auditLog.forceNewChain("test_reset");

      expect(auditLog.getCheckpointSequence()).toBe(0);
      expect(auditLog.getRecordCount()).toBe(0);
    });

    it("refuses to start with corrupt state file", async () => {
      const statePath = TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json");
      await writeFile(statePath, "not valid json{{{");

      const newLog = new AuditLog(TEST_AUDIT_PATH, signer, 100 * 1024 * 1024);
      await expect(newLog.init()).rejects.toThrow("state file corrupt");
    });

    it("refuses to start when rotationBoundaryHash doesn't match first record", async () => {
      // Write a record with previousHash = "genesis"
      await auditLog.record("tools/call", {
        toolName: "t1",
        namespace: "ns",
        upstream: "up",
        durationMs: 10,
        success: true,
      });
      // Plant a state file with wrong rotationBoundaryHash
      const statePath = TEST_AUDIT_PATH.replace(/\.jsonl$/, ".state.json");
      await writeFile(statePath, JSON.stringify({
        lastHash: "whatever",
        rotationBoundaryHash: "planted_wrong_boundary",
        checkpointSequence: 0,
        totalRecordCount: 0,
      }));

      const newLog = new AuditLog(TEST_AUDIT_PATH, signer, 100 * 1024 * 1024);
      await expect(newLog.init()).rejects.toThrow("state file inconsistent");
    });

    it("forceNewChain mid-file does not brick next restart", async () => {
      // Write some records, then force a chain break mid-file
      await auditLog.record("tools/call", {
        toolName: "t1",
        namespace: "ns",
        upstream: "up",
        durationMs: 10,
        success: true,
      });
      await auditLog.forceNewChain("operator_test");

      // Write one more record after the break
      await auditLog.record("tools/call", {
        toolName: "t2",
        namespace: "ns",
        upstream: "up",
        durationMs: 10,
        success: true,
      });

      // Restart — should NOT throw, because rotationBoundaryHash was not
      // overwritten by forceNewChain (only lastHash was)
      const newLog = new AuditLog(TEST_AUDIT_PATH, signer, 100 * 1024 * 1024);
      await newLog.init();
      // Should resume successfully — the first record's previousHash is "genesis"
      // and rotationBoundaryHash should be null (no rotation happened)
      expect(newLog.getLastHash()).not.toBe("genesis");
    });

    it("break then rotate then restart succeeds", async () => {
      const rotatePath = "/tmp/break-rotate-restart.jsonl";
      const stateFile = rotatePath.replace(/\.jsonl$/, ".state.json");
      try { await unlink(rotatePath); } catch {}
      try { await unlink(stateFile); } catch {}

      // Use tiny rotate threshold so the second record triggers rotation
      const log1 = new AuditLog(rotatePath, signer, 1);
      await log1.init();

      // Write one record (triggers rotation due to tiny threshold)
      await log1.record("tools/call", {
        toolName: "t1",
        namespace: "ns",
        upstream: "up",
        durationMs: 10,
        success: true,
      });

      // Force a chain break on the new (rotated) file
      await log1.forceNewChain("test_break_after_rotate");

      // Write a record after the break (triggers another rotation)
      await log1.record("tools/call", {
        toolName: "t2",
        namespace: "ns",
        upstream: "up",
        durationMs: 10,
        success: true,
      });

      // Restart — linkage check should pass: rotationBoundaryHash
      // was set by the last rotation, and the first record of the new
      // file chains from that hash.
      const log2 = new AuditLog(rotatePath, signer, 100 * 1024 * 1024);
      await log2.init();
      expect(log2.getLastHash()).not.toBe("genesis");

      // Cleanup rotated files
      const { readdir } = await import("node:fs/promises");
      const dir = await readdir("/tmp");
      for (const f of dir) {
        if (f.startsWith("break-rotate-restart") && f !== "break-rotate-restart.jsonl") {
          try { await unlink(`/tmp/${f}`); } catch {}
        }
      }
      try { await unlink(rotatePath); } catch {}
      try { await unlink(stateFile); } catch {}
    });

    it("starts fresh when no state file and no log exist", async () => {
      const freshPath = "/tmp/fresh-test-audit.jsonl";
      try { await unlink(freshPath); } catch {}
      try { await unlink(freshPath.replace(/\.jsonl$/, ".state.json")); } catch {}

      const freshLog = new AuditLog(freshPath, signer, 100 * 1024 * 1024);
      await freshLog.init();
      expect(freshLog.getLastHash()).toBe("genesis");
    });
  });

  describe("verification modes", () => {
    it("relative mode accepts descendant with absoluteCountVerified=false", () => {
      const chain: ChainRecord[] = [
        {
          id: "ckpt_5",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:05.000Z",
          sequence: 5,
          recordCount: 50,
          previousHash: "hhh",
        } as CheckpointRecord,
      ];

      const result = verifyCompleteness(
        chain,
        { previousHash: "earlier_hash", sequence: 3, recordCount: 30 },
        { mode: "relative" },
      );

      expect(result.truncated).toBe(false);
      expect(result.absoluteCountVerified).toBe(false);
      expect(result.verificationMode).toBe("relative");
    });

    it("strict mode sets absoluteCountVerified=true on success", async () => {
      auditLog.enableCheckpoints({
        enabled: true,
        intervalRecords: 3,
        intervalSeconds: 9999,
        trigger: "records",
      });

      for (let i = 0; i < 4; i++) {
        await auditLog.record("tools/call", {
          toolName: `tool_${i}`,
          namespace: "ns",
          upstream: "srv",
          durationMs: 10,
          success: true,
        });
      }

      const records = await readAllRecords(TEST_AUDIT_PATH);
      const checkpoint = records.find(isCheckpoint) as CheckpointRecord;

      const result = verifyCompleteness(records, {
        previousHash: checkpoint.previousHash,
        sequence: checkpoint.sequence,
        recordCount: checkpoint.recordCount,
      }, { mode: "strict" });

      expect(result.truncated).toBe(false);
      expect(result.absoluteCountVerified).toBe(true);
      expect(result.verificationMode).toBe("strict");
    });

    it("chain with break does not false-positive on sequence regression", () => {
      const chain: ChainRecord[] = [
        {
          id: "ckpt_pre",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:00.000Z",
          sequence: 5,
          recordCount: 50,
          previousHash: "pre_hash",
        } as CheckpointRecord,
        {
          id: "break_1",
          type: "chain_break",
          timestamp: "2026-08-22T20:00:01.000Z",
          reason: "operator_override",
          priorHead: "pre_hash",
          priorSequence: 5,
          priorRecordCount: 50,
        } as ChainBreakRecord,
        {
          id: "ckpt_post",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:02.000Z",
          sequence: 1,
          recordCount: 3,
          previousHash: "post_hash",
        } as CheckpointRecord,
      ];

      // Externalize the pre-break checkpoint
      const result = verifyCompleteness(chain, {
        previousHash: "pre_hash",
        sequence: 5,
        recordCount: 50,
      });

      // Should NOT report sequence_regression: break resets legitimately
      expect(result.failureCode).not.toBe("sequence_regression");
    });

    it("still catches regression within a segment after break", () => {
      const chain: ChainRecord[] = [
        {
          id: "break_1",
          type: "chain_break",
          timestamp: "2026-08-22T20:00:00.000Z",
          reason: "test",
        } as ChainBreakRecord,
        {
          id: "ckpt_1",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:01.000Z",
          sequence: 3,
          recordCount: 10,
          previousHash: "aaa",
        } as CheckpointRecord,
        {
          id: "ckpt_2",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:02.000Z",
          sequence: 2,
          recordCount: 15,
          previousHash: "bbb",
        } as CheckpointRecord,
      ];

      const result = verifyCompleteness(chain, {
        previousHash: "aaa",
        sequence: 3,
        recordCount: 10,
      });

      expect(result.truncated).toBe(true);
      expect(result.failureCode).toBe("sequence_regression");
    });

    it("detects adjacent-pair delta mismatch", () => {
      const chain: ChainRecord[] = [
        {
          id: "rec1",
          timestamp: "2026-08-22T20:00:00.000Z",
          method: "tools/call",
          toolName: "t1",
          durationMs: 10,
          success: true,
          previousHash: "genesis",
        } as AuditRecord,
        {
          id: "ckpt_1",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:01.000Z",
          sequence: 1,
          recordCount: 1,
          previousHash: "aaa",
        } as CheckpointRecord,
        // Only 1 record between checkpoints, but ckpt_2 claims delta of 5
        {
          id: "rec2",
          timestamp: "2026-08-22T20:00:02.000Z",
          method: "tools/call",
          toolName: "t2",
          durationMs: 10,
          success: true,
          previousHash: "bbb",
        } as AuditRecord,
        {
          id: "ckpt_2",
          type: "checkpoint",
          timestamp: "2026-08-22T20:00:03.000Z",
          sequence: 2,
          recordCount: 6, // claims 6 total (delta of 5 from ckpt_1), but only 1 record between
          previousHash: "ccc",
        } as CheckpointRecord,
      ];

      const result = verifyCompleteness(chain, {
        previousHash: "aaa",
        sequence: 1,
        recordCount: 1,
      });

      expect(result.truncated).toBe(true);
      expect(result.failureCode).toBe("count_mismatch");
      expect(result.reason).toContain("adjacent checkpoint delta mismatch");
    });
  });
});

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, unlink, readFile } from "node:fs/promises";
import { HmacSigner } from "./signer.js";
import { AuditLog, hashRecord } from "./audit-log.js";
import { verifyAuditLog } from "./verify.js";
import type { AuditRecord } from "../types.js";

const TEST_LOG = "/tmp/bugfix-audit.jsonl";
const SECRET = "d".repeat(64);

describe("Bug fix: pipe injection in canonicalization", () => {
  const signer = new HmacSigner(SECRET);

  it("different records with pipe chars produce different signatures", async () => {
    const record1: AuditRecord = {
      id: "uuid-1",
      timestamp: "2026-08-16T10:00:00Z",
      method: "tools/call",
      toolName: "db/read|admin",
      namespace: "db",
      upstream: "evil",
      principal: "alice",
      durationMs: 50,
      success: true,
    };

    const record2: AuditRecord = {
      id: "uuid-1",
      timestamp: "2026-08-16T10:00:00Z",
      method: "tools/call",
      toolName: "db/read",
      namespace: "admin",
      upstream: "db",
      principal: "evil|alice",
      durationMs: 50,
      success: true,
    };

    const sig1 = await signer.sign(record1);
    const sig2 = await signer.sign(record2);
    expect(sig1).not.toBe(sig2);
  });
});

describe("Bug fix: hash chain survives restart", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => { try { await unlink(TEST_LOG); } catch {} });
  afterEach(async () => { try { await unlink(TEST_LOG); } catch {} });

  it("restores lastHash from existing log on init", async () => {
    const log1 = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log1.init();
    await log1.record("tools/call", { toolName: "test/a", durationMs: 10, success: true });
    await log1.record("tools/call", { toolName: "test/b", durationMs: 10, success: true });

    const log2 = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log2.init();
    await log2.record("tools/call", { toolName: "test/c", durationMs: 10, success: true });

    const result = await verifyAuditLog(TEST_LOG, signer, { verifyChain: true });
    expect(result.total).toBe(3);
    expect(result.valid).toBe(3);
    expect(result.invalid).toBe(0);
  });
});

describe("Bug fix: concurrent writes maintain chain integrity", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => { try { await unlink(TEST_LOG); } catch {} });
  afterEach(async () => { try { await unlink(TEST_LOG); } catch {} });

  it("serializes concurrent writes correctly", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", { toolName: "test/setup", durationMs: 10, success: true });

    const concurrent = Array.from({ length: 10 }, (_, i) =>
      log.record("tools/call", { toolName: `test/tool_${i}`, durationMs: i, success: true })
    );
    await Promise.all(concurrent);

    const content = await readFile(TEST_LOG, "utf-8");
    const records: AuditRecord[] = content.trimEnd().split("\n").map((l) => JSON.parse(l));
    expect(records).toHaveLength(11);

    const previousHashes = records.map((r) => r.previousHash);
    const unique = new Set(previousHashes);
    expect(unique.size).toBe(11);

    for (let i = 1; i < records.length; i++) {
      const expected = hashRecord(records[i - 1]);
      expect(records[i].previousHash).toBe(expected);
    }
  });
});

describe("Bug fix: glob matcher prefix/suffix overlap", () => {
  it("does not match when prefix and suffix overlap", async () => {
    const { PolicyEngine } = await import("../policy/engine.js");
    const engine = new PolicyEngine("allow", []);
    const match = (engine as any).globMatch.bind(engine);

    expect(match("ab*ab", "ab")).toBe(false);
    expect(match("admin*admin", "admin")).toBe(false);
    expect(match("ab*ab", "abab")).toBe(true);
    expect(match("ab*ab", "abXab")).toBe(true);
    expect(match("*/write_*", "fs/write_file")).toBe(true);
    expect(match("agent:readonly-*", "agent:readonly-bot")).toBe(true);
  });
});

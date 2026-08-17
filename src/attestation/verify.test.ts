import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, unlink } from "node:fs/promises";
import { HmacSigner } from "./signer.js";
import { AuditLog } from "./audit-log.js";
import { verifyAuditLog } from "./verify.js";

const TEST_LOG = "/tmp/test-verify-audit.jsonl";
const SECRET = "b".repeat(64);

describe("verifyAuditLog", () => {
  const signer = new HmacSigner(SECRET);

  beforeEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });

  afterEach(async () => {
    try { await unlink(TEST_LOG); } catch {}
  });

  it("verifies a valid audit log", async () => {
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

    const result = await verifyAuditLog(TEST_LOG, signer);
    expect(result.total).toBe(2);
    expect(result.valid).toBe(2);
    expect(result.invalid).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it("detects tampered records", async () => {
    const log = new AuditLog(TEST_LOG, signer, 100 * 1024 * 1024);
    await log.init();

    await log.record("tools/call", {
      toolName: "test/tool_a",
      durationMs: 100,
      success: true,
    });

    const { readFile: rf } = await import("node:fs/promises");
    const content = await rf(TEST_LOG, "utf-8");
    const tampered = content.replace('"success":true', '"success":false');
    await writeFile(TEST_LOG, tampered);

    const result = await verifyAuditLog(TEST_LOG, signer);
    expect(result.total).toBe(1);
    expect(result.invalid).toBe(1);
    expect(result.errors[0].reason).toBe("signature mismatch");
  });

  it("detects missing attestation", async () => {
    const record = JSON.stringify({
      id: "no-sig",
      timestamp: "2026-08-16T10:00:00Z",
      method: "tools/call",
      durationMs: 50,
      success: true,
    });
    await writeFile(TEST_LOG, record + "\n");

    const result = await verifyAuditLog(TEST_LOG, signer);
    expect(result.total).toBe(1);
    expect(result.invalid).toBe(1);
    expect(result.errors[0].reason).toBe("missing attestation");
  });
});

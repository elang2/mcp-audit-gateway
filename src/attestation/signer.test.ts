import { describe, it, expect } from "vitest";
import { HmacSigner, Ed25519Signer } from "./signer.js";
import type { AuditRecord } from "../types.js";

const mockRecord: AuditRecord = {
  id: "test-uuid-001",
  timestamp: "2026-08-16T10:00:00.000Z",
  method: "tools/call",
  toolName: "github/create_pr",
  namespace: "github",
  upstream: "github-server",
  principal: "agent:dev-bot",
  durationMs: 234,
  success: true,
};

describe("HmacSigner", () => {
  const secret = "a".repeat(64);
  const signer = new HmacSigner(secret);

  it("produces a hex signature", async () => {
    const sig = await signer.sign(mockRecord);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies a valid signature", async () => {
    const sig = await signer.sign(mockRecord);
    const valid = await signer.verify(mockRecord, sig);
    expect(valid).toBe(true);
  });

  it("rejects a tampered record", async () => {
    const sig = await signer.sign(mockRecord);
    const tampered = { ...mockRecord, durationMs: 999 };
    const valid = await signer.verify(tampered, sig);
    expect(valid).toBe(false);
  });

  it("rejects a wrong signature", async () => {
    const valid = await signer.verify(mockRecord, "bad".repeat(21) + "b");
    expect(valid).toBe(false);
  });
});

describe("Ed25519Signer", () => {
  it("signs and verifies a record", async () => {
    const signer = new Ed25519Signer();
    await signer.init();

    const sig = await signer.sign(mockRecord);
    expect(sig.length).toBeGreaterThan(100);

    const valid = await signer.verify(mockRecord, sig);
    expect(valid).toBe(true);
  });

  it("rejects a tampered record", async () => {
    const signer = new Ed25519Signer();
    await signer.init();

    const sig = await signer.sign(mockRecord);
    const tampered = { ...mockRecord, success: false };
    const valid = await signer.verify(tampered, sig);
    expect(valid).toBe(false);
  });

  it("exposes the public key for external verification", async () => {
    const signer = new Ed25519Signer();
    await signer.init();

    const pubKey = signer.getPublicKey();
    expect(pubKey).not.toBeNull();
    expect(pubKey!.length).toBe(32);
  });
});

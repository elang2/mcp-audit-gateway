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

describe("decisionContextDigest in signatures", () => {
  const secret = "b".repeat(64);
  const signer = new HmacSigner(secret);

  const recordWithDigest: AuditRecord = {
    ...mockRecord,
    id: "test-uuid-002",
    decisionContextDigest: "c".repeat(64),
  };

  it("includes digest in signature when present", async () => {
    const sigWith = await signer.sign(recordWithDigest);
    const sigWithout = await signer.sign(mockRecord);
    expect(sigWith).not.toBe(sigWithout);
  });

  it("verifies record with digest", async () => {
    const sig = await signer.sign(recordWithDigest);
    const valid = await signer.verify(recordWithDigest, sig);
    expect(valid).toBe(true);
  });

  it("rejects tampered digest", async () => {
    const sig = await signer.sign(recordWithDigest);
    const tampered = { ...recordWithDigest, decisionContextDigest: "d".repeat(64) };
    const valid = await signer.verify(tampered, sig);
    expect(valid).toBe(false);
  });

  it("old records without digest still verify", async () => {
    const oldRecord: AuditRecord = { ...mockRecord, id: "old-record-001" };
    const sig = await signer.sign(oldRecord);
    const valid = await signer.verify(oldRecord, sig);
    expect(valid).toBe(true);
  });
});

describe("parties in signatures", () => {
  const secret = "c".repeat(64);
  const signer = new HmacSigner(secret);

  const recordWithParties: AuditRecord = {
    ...mockRecord,
    id: "test-uuid-parties-001",
    parties: [
      { party: "gateway", role: "witness", scope: ["id", "timestamp", "method", "toolName", "namespace", "upstream", "principal", "durationMs", "success", "errorCode", "previousHash"] },
    ],
  };

  it("includes parties in signature when present", async () => {
    const sigWith = await signer.sign(recordWithParties);
    const sigWithout = await signer.sign(mockRecord);
    expect(sigWith).not.toBe(sigWithout);
  });

  it("verifies record with parties", async () => {
    const sig = await signer.sign(recordWithParties);
    const valid = await signer.verify(recordWithParties, sig);
    expect(valid).toBe(true);
  });

  it("rejects tampered parties", async () => {
    const sig = await signer.sign(recordWithParties);
    const tampered = { ...recordWithParties, parties: [{ party: "attacker", role: "asserter" as const, scope: ["*"] }] };
    const valid = await signer.verify(tampered, sig);
    expect(valid).toBe(false);
  });

  it("handles both decisionContextDigest and parties together", async () => {
    const dual: AuditRecord = {
      ...recordWithParties,
      id: "test-uuid-parties-002",
      decisionContextDigest: "e".repeat(64),
      parties: [
        { party: "gateway", role: "witness", scope: ["id", "timestamp", "method"] },
        { party: "policy-engine", role: "asserter", scope: ["decisionContextDigest"] },
      ],
    };
    const sig = await signer.sign(dual);
    const valid = await signer.verify(dual, sig);
    expect(valid).toBe(true);
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

  it("rejects signature from a different key (signature substitution)", async () => {
    const signerA = new Ed25519Signer();
    await signerA.init();
    const signerB = new Ed25519Signer();
    await signerB.init();

    const sigFromA = await signerA.sign(mockRecord);
    const validOnA = await signerA.verify(mockRecord, sigFromA);
    expect(validOnA).toBe(true);

    const validOnB = await signerB.verify(mockRecord, sigFromA);
    expect(validOnB).toBe(false);
  });
});

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { AttestationConfig, AuditRecord, CheckpointRecord, ChainBreakRecord, ChainRecord } from "../types.js";
import { isCheckpoint, isChainBreak } from "../types.js";

export interface Signer {
  sign(record: AuditRecord | CheckpointRecord | ChainBreakRecord): Promise<string>;
  verify(record: AuditRecord | CheckpointRecord | ChainBreakRecord, signature: string): Promise<boolean>;
}

export class HmacSigner implements Signer {
  private secret: Buffer;

  constructor(secret: string) {
    this.secret = Buffer.from(secret, "hex");
  }

  async sign(record: AuditRecord | CheckpointRecord | ChainBreakRecord): Promise<string> {
    const payload = isChainBreak(record)
      ? canonicalizeChainBreak(record)
      : isCheckpoint(record)
        ? canonicalizeCheckpoint(record)
        : canonicalizeRecord(record);
    const hmac = createHmac("sha256", this.secret);
    hmac.update(payload);
    return hmac.digest("hex");
  }

  async verify(record: AuditRecord | CheckpointRecord | ChainBreakRecord, signature: string): Promise<boolean> {
    const expected = await this.sign(record);
    const expectedBuf = Buffer.from(expected, "hex");
    const signatureBuf = Buffer.from(signature, "hex");
    if (expectedBuf.length !== signatureBuf.length) return false;
    return timingSafeEqual(expectedBuf, signatureBuf);
  }
}

export class Ed25519Signer implements Signer {
  private privateKey: Uint8Array | null = null;
  private publicKey: Uint8Array | null = null;

  constructor(private keyPath?: string) {}

  async init(): Promise<void> {
    const ed = await import("@noble/ed25519");
    if (this.keyPath) {
      const { readFile } = await import("node:fs/promises");
      const keyData = await readFile(this.keyPath);
      this.privateKey = new Uint8Array(keyData);
    } else {
      this.privateKey = ed.utils.randomPrivateKey();
    }
    this.publicKey = await ed.getPublicKeyAsync(this.privateKey);
  }

  async sign(record: AuditRecord | CheckpointRecord | ChainBreakRecord): Promise<string> {
    if (!this.privateKey) await this.init();
    const ed = await import("@noble/ed25519");
    const canonical = isChainBreak(record)
      ? canonicalizeChainBreak(record)
      : isCheckpoint(record)
        ? canonicalizeCheckpoint(record)
        : canonicalizeRecord(record);
    const payload = new TextEncoder().encode(canonical);
    const sig = await ed.signAsync(payload, this.privateKey!);
    return Buffer.from(sig).toString("hex");
  }

  async verify(record: AuditRecord | CheckpointRecord | ChainBreakRecord, signature: string): Promise<boolean> {
    if (!this.publicKey) await this.init();
    const ed = await import("@noble/ed25519");
    const canonical = isChainBreak(record)
      ? canonicalizeChainBreak(record)
      : isCheckpoint(record)
        ? canonicalizeCheckpoint(record)
        : canonicalizeRecord(record);
    const payload = new TextEncoder().encode(canonical);
    const sig = Buffer.from(signature, "hex");
    return ed.verifyAsync(sig, payload, this.publicKey!);
  }

  getPublicKey(): Uint8Array | null {
    return this.publicKey;
  }
}

export function assertWellFormedString(value: string, context: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xD800 && code <= 0xDBFF) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) {
        throw new Error(`${context}: unpaired surrogate at index ${i}`);
      }
      i++;
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      throw new Error(`${context}: unpaired surrogate at index ${i}`);
    }
  }
}

export function canonicalizeRecord(record: AuditRecord): string {
  assertWellFormedString(record.id, "canonicalizeRecord.id");
  assertWellFormedString(record.timestamp, "canonicalizeRecord.timestamp");
  assertWellFormedString(record.method, "canonicalizeRecord.method");
  if (record.toolName != null) assertWellFormedString(record.toolName, "canonicalizeRecord.toolName");
  if (record.namespace != null) assertWellFormedString(record.namespace, "canonicalizeRecord.namespace");
  if (record.upstream != null) assertWellFormedString(record.upstream, "canonicalizeRecord.upstream");
  if (record.principal != null) assertWellFormedString(record.principal, "canonicalizeRecord.principal");
  if (record.previousHash != null) assertWellFormedString(record.previousHash, "canonicalizeRecord.previousHash");
  if (record.decisionContextDigest != null) assertWellFormedString(record.decisionContextDigest, "canonicalizeRecord.decisionContextDigest");
  if (record.extensionsDigest != null) assertWellFormedString(record.extensionsDigest, "canonicalizeRecord.extensionsDigest");

  const ordered: [string, string | number | boolean | null | unknown][] = [
    ["id", record.id],
    ["timestamp", record.timestamp],
    ["method", record.method],
    ["toolName", record.toolName ?? null],
    ["namespace", record.namespace ?? null],
    ["upstream", record.upstream ?? null],
    ["principal", record.principal ?? null],
    ["durationMs", record.durationMs],
    ["success", record.success],
    ["errorCode", record.errorCode ?? null],
    ["previousHash", record.previousHash ?? null],
  ];
  // Conditional fields inserted in deterministic order:
  // 1. decisionContextDigest (position 10, before previousHash moves to 11)
  // 2. extensionsDigest (after decisionContextDigest or at position 11)
  // 3. aiInvocation (after extensionsDigest; M/L-tagged via canonicalizeValue)
  // 4. parties (last)
  let insertAt = 11;
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
    insertAt = 12;
  }
  if (record.extensionsDigest != null) {
    ordered.splice(insertAt, 0, ["extensionsDigest", record.extensionsDigest]);
    insertAt++;
  }
  if (record.aiInvocation != null) {
    ordered.splice(insertAt, 0, ["aiInvocation", canonicalizeValue(record.aiInvocation)]);
    insertAt++;
  }
  if (record.parties != null) {
    ordered.splice(insertAt, 0, ["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

export function canonicalizeCheckpoint(record: CheckpointRecord): string {
  assertWellFormedString(record.id, "canonicalizeCheckpoint.id");
  assertWellFormedString(record.timestamp, "canonicalizeCheckpoint.timestamp");
  assertWellFormedString(record.previousHash, "canonicalizeCheckpoint.previousHash");

  const ordered: [string, string | number | null | unknown][] = [
    ["id", record.id],
    ["type", "checkpoint"],
    ["timestamp", record.timestamp],
    ["sequence", record.sequence],
    ["recordCount", record.recordCount],
    ["previousHash", record.previousHash],
  ];
  if (record.parties != null) {
    ordered.push(["parties", record.parties]);
  }
  return JSON.stringify(ordered);
}

export function canonicalizeChainBreak(record: ChainBreakRecord): string {
  assertWellFormedString(record.id, "canonicalizeChainBreak.id");
  assertWellFormedString(record.timestamp, "canonicalizeChainBreak.timestamp");
  assertWellFormedString(record.reason, "canonicalizeChainBreak.reason");
  if (record.priorHead != null) assertWellFormedString(record.priorHead, "canonicalizeChainBreak.priorHead");

  const ordered: [string, string | number | null][] = [
    ["id", record.id],
    ["type", "chain_break"],
    ["timestamp", record.timestamp],
    ["reason", record.reason],
    ["priorHead", record.priorHead ?? null],
    ["priorSequence", record.priorSequence ?? null],
    ["priorRecordCount", record.priorRecordCount ?? null],
  ];
  return JSON.stringify(ordered);
}

/**
 * Recursively canonicalize a value for deterministic, injective serialization.
 *
 * Objects become ["M", [[k,v],...]] (sorted pairs). Arrays become ["L", [...]].
 * Type tags make the mapping injective: {a:1} and [["a",1]] produce distinct
 * canonical forms, preventing type-confusion collisions in digests.
 *
 * Numbers must be safe integers — floats/unsafe integers throw (callers must
 * pre-encode as strings). Strings, booleans, and null pass through as scalars.
 * Keys with undefined values are dropped (matches JSON.stringify and Python).
 */
export function canonicalizeValue(value: unknown): unknown {
  if (value === null || value === undefined) return null;

  switch (typeof value) {
    case "string":
      assertWellFormedString(value, "canonicalizeValue");
      return value;
    case "boolean":
      return value;
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new Error(
          `canonicalizeValue: unsafe number ${value}. ` +
          `Only safe integers are allowed; encode floats/large numbers as strings.`
        );
      }
      return value;
    case "object":
      if (Array.isArray(value)) {
        return ["L", value.map(canonicalizeValue)];
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort().filter(k => obj[k] !== undefined);
      for (const k of keys) {
        assertWellFormedString(k, "canonicalizeValue.key");
      }
      return ["M", keys.map(k => [k, canonicalizeValue(obj[k])])];
    default:
      throw new Error(`canonicalizeValue: unsupported type ${typeof value}`);
  }
}

export function computeExtensionsDigest(extensions: Record<string, unknown>): string {
  const canonicalized = canonicalizeValue(extensions);
  const serialized = JSON.stringify(canonicalized);
  return createHash("sha256").update(serialized).digest("hex");
}

export function createSigner(config: AttestationConfig): Signer {
  if (!config.enabled) {
    return { sign: async () => "", verify: async () => true };
  }
  if (config.algorithm === "hmac-sha256") {
    const secret = config.secret ?? randomBytes(32).toString("hex");
    return new HmacSigner(secret);
  }
  return new Ed25519Signer(config.keyPath);
}

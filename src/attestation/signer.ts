import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { AttestationConfig, AuditRecord } from "../types.js";

export interface Signer {
  sign(record: AuditRecord): Promise<string>;
  verify(record: AuditRecord, signature: string): Promise<boolean>;
}

export class HmacSigner implements Signer {
  private secret: Buffer;

  constructor(secret: string) {
    this.secret = Buffer.from(secret, "hex");
  }

  async sign(record: AuditRecord): Promise<string> {
    const payload = this.canonicalize(record);
    const hmac = createHmac("sha256", this.secret);
    hmac.update(payload);
    return hmac.digest("hex");
  }

  async verify(record: AuditRecord, signature: string): Promise<boolean> {
    const expected = await this.sign(record);
    const expectedBuf = Buffer.from(expected, "hex");
    const signatureBuf = Buffer.from(signature, "hex");
    if (expectedBuf.length !== signatureBuf.length) return false;
    return timingSafeEqual(expectedBuf, signatureBuf);
  }

  private canonicalize(record: AuditRecord): string {
    return canonicalizeRecord(record);
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

  async sign(record: AuditRecord): Promise<string> {
    if (!this.privateKey) await this.init();
    const ed = await import("@noble/ed25519");
    const payload = new TextEncoder().encode(this.canonicalize(record));
    const sig = await ed.signAsync(payload, this.privateKey!);
    return Buffer.from(sig).toString("hex");
  }

  async verify(record: AuditRecord, signature: string): Promise<boolean> {
    if (!this.publicKey) await this.init();
    const ed = await import("@noble/ed25519");
    const payload = new TextEncoder().encode(this.canonicalize(record));
    const sig = Buffer.from(signature, "hex");
    return ed.verifyAsync(sig, payload, this.publicKey!);
  }

  getPublicKey(): Uint8Array | null {
    return this.publicKey;
  }

  private canonicalize(record: AuditRecord): string {
    return canonicalizeRecord(record);
  }
}

function canonicalizeRecord(record: AuditRecord): string {
  const ordered: [string, string | number | boolean | null][] = [
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
  if (record.decisionContextDigest != null) {
    ordered.splice(10, 0, ["decisionContextDigest", record.decisionContextDigest]);
  }
  return JSON.stringify(ordered);
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

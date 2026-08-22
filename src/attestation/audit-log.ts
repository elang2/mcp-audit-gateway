import { appendFile, stat, rename, open } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import type { AuditRecord } from "../types.js";
import type { Signer } from "./signer.js";

export function hashRecord(record: AuditRecord): string {
  const json = JSON.stringify(record);
  return createHash("sha256").update(json).digest("hex");
}

export class AuditLog {
  private currentSize = 0;
  private lastHash: string = "genesis";
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(
    private path: string,
    private signer: Signer,
    private rotateAfterBytes: number,
  ) {}

  async record(
    method: string,
    opts: {
      toolName?: string;
      namespace?: string;
      upstream?: string;
      principal?: string;
      durationMs: number;
      success: boolean;
      errorCode?: number;
      decisionContextDigest?: string;
    },
  ): Promise<AuditRecord> {
    return new Promise((resolve, reject) => {
      this.writeQueue = this.writeQueue.then(async () => {
        try {
          const result = await this.writeRecord(method, opts);
          resolve(result);
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  private async writeRecord(
    method: string,
    opts: {
      toolName?: string;
      namespace?: string;
      upstream?: string;
      principal?: string;
      durationMs: number;
      success: boolean;
      errorCode?: number;
      decisionContextDigest?: string;
    },
  ): Promise<AuditRecord> {
    const record: AuditRecord = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      method,
      ...opts,
      previousHash: this.lastHash,
    };

    record.attestation = await this.signer.sign(record);
    const line = JSON.stringify(record) + "\n";

    await appendFile(this.path, line);
    this.currentSize += Buffer.byteLength(line);

    this.lastHash = hashRecord(record);

    if (this.currentSize >= this.rotateAfterBytes) {
      await this.rotate();
    }

    return record;
  }

  private async rotate(): Promise<void> {
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const rotatedPath = this.path.replace(/\.jsonl$/, `-${ts}.jsonl`);
    try {
      await rename(this.path, rotatedPath);
      this.currentSize = 0;
      this.lastHash = "genesis";
    } catch {}
  }

  async init(): Promise<void> {
    let s;
    try {
      s = await stat(this.path);
    } catch {
      this.currentSize = 0;
      return;
    }

    this.currentSize = s.size;

    if (s.size > 0) {
      const tailSize = Math.min(s.size, 8192);
      const fh = await open(this.path, "r");
      try {
        const buf = Buffer.alloc(tailSize);
        await fh.read(buf, 0, tailSize, s.size - tailSize);
        const tail = buf.toString("utf-8");
        const lines = tail.trimEnd().split("\n");
        for (let i = lines.length - 1; i >= 0; i--) {
          try {
            const record: AuditRecord = JSON.parse(lines[i]);
            this.lastHash = hashRecord(record);
            return;
          } catch {
            process.stderr.write(
              `[audit-log] warning: corrupt record in tail, skipping\n`,
            );
          }
        }
      } finally {
        await fh.close();
      }
    }
  }
}

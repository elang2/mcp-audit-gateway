import { appendFile, stat, rename, open, writeFile as fsWriteFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import type { AuditRecord, CheckpointRecord, ChainBreakRecord, PartyAttribution, ChainRecord } from "../types.js";
import { isCheckpoint, isChainBreak } from "../types.js";
import type { Signer } from "./signer.js";

const GATEWAY_WITNESSED_FIELDS = [
  "id", "timestamp", "method", "toolName", "namespace",
  "upstream", "principal", "durationMs", "success", "errorCode",
  "previousHash",
];

function buildParties(hasDecisionContext: boolean): PartyAttribution[] {
  const parties: PartyAttribution[] = [
    { party: "gateway", role: "witness", scope: GATEWAY_WITNESSED_FIELDS },
  ];
  if (hasDecisionContext) {
    parties.push({
      party: "policy-engine",
      role: "asserter",
      scope: ["decisionContextDigest"],
    });
  }
  return parties;
}

export function hashRecord(record: AuditRecord | CheckpointRecord | ChainBreakRecord): string {
  const json = JSON.stringify(record);
  return createHash("sha256").update(json).digest("hex");
}

export interface CheckpointConfig {
  enabled: boolean;
  intervalRecords: number;
  intervalSeconds: number;
  trigger: "records" | "time" | "whichever_first";
}

export class AuditLog {
  private currentSize = 0;
  private lastHash: string = "genesis";
  private writeQueue: Promise<void> = Promise.resolve();
  private recordsSinceCheckpoint = 0;
  private lastCheckpointTime = Date.now();
  private checkpointSequence = 0;
  private totalRecordCount = 0;
  private checkpointConfig: CheckpointConfig | null = null;

  constructor(
    private path: string,
    private signer: Signer,
    private rotateAfterBytes: number,
  ) {}

  enableCheckpoints(config: CheckpointConfig): void {
    this.checkpointConfig = config;
  }

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
      parties: buildParties(opts.decisionContextDigest != null),
      previousHash: this.lastHash,
    };

    record.attestation = await this.signer.sign(record);
    const line = JSON.stringify(record) + "\n";

    await appendFile(this.path, line);
    this.currentSize += Buffer.byteLength(line);

    this.lastHash = hashRecord(record);
    this.totalRecordCount++;
    this.recordsSinceCheckpoint++;

    if (this.shouldEmitCheckpoint()) {
      await this.writeCheckpoint();
    }

    if (this.currentSize >= this.rotateAfterBytes) {
      await this.rotate();
    }

    return record;
  }

  private shouldEmitCheckpoint(): boolean {
    if (!this.checkpointConfig?.enabled) return false;
    const { trigger, intervalRecords, intervalSeconds } = this.checkpointConfig;
    const recordsHit = this.recordsSinceCheckpoint >= intervalRecords;
    const timeHit = (Date.now() - this.lastCheckpointTime) >= intervalSeconds * 1000;

    if (trigger === "records") return recordsHit;
    if (trigger === "time") return timeHit;
    return recordsHit || timeHit;
  }

  private async writeCheckpoint(): Promise<CheckpointRecord> {
    this.checkpointSequence++;
    const checkpoint: CheckpointRecord = {
      id: `ckpt_${randomUUID()}`,
      type: "checkpoint",
      timestamp: new Date().toISOString(),
      sequence: this.checkpointSequence,
      recordCount: this.totalRecordCount,
      previousHash: this.lastHash,
      parties: [{ party: "gateway", role: "witness", scope: ["sequence", "recordCount", "previousHash"] }],
    };

    checkpoint.attestation = await this.signer.sign(checkpoint);
    const line = JSON.stringify(checkpoint) + "\n";

    await appendFile(this.path, line);
    this.currentSize += Buffer.byteLength(line);

    this.lastHash = hashRecord(checkpoint);
    this.recordsSinceCheckpoint = 0;
    this.lastCheckpointTime = Date.now();

    return checkpoint;
  }

  async emitCheckpoint(): Promise<CheckpointRecord> {
    return new Promise((resolve, reject) => {
      this.writeQueue = this.writeQueue.then(async () => {
        try {
          const result = await this.writeCheckpoint();
          resolve(result);
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  getLastHash(): string {
    return this.lastHash;
  }

  getCheckpointSequence(): number {
    return this.checkpointSequence;
  }

  getRecordCount(): number {
    return this.totalRecordCount;
  }

  private async rotate(): Promise<void> {
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const rotatedPath = this.path.replace(/\.jsonl$/, `-${ts}.jsonl`);
    try {
      await rename(this.path, rotatedPath);
      this.currentSize = 0;
      // Chain-global: lastHash, sequence, recordCount survive rotation.
      // The first record in the new file chains to the last hash of the
      // previous file. Resetting to "genesis" would allow truncation-via-rotation.
      await this.persistState();
    } catch {}
  }

  private rotationBoundaryHash: string = "genesis";

  private async persistState(): Promise<void> {
    const statePath = this.path.replace(/\.jsonl$/, ".state.json");
    const tmpPath = statePath + ".tmp";
    const state = {
      lastHash: this.lastHash,
      rotationBoundaryHash: this.lastHash,
      checkpointSequence: this.checkpointSequence,
      totalRecordCount: this.totalRecordCount,
    };
    await fsWriteFile(tmpPath, JSON.stringify(state));
    await rename(tmpPath, statePath);
  }

  private async persistChainState(): Promise<void> {
    const statePath = this.path.replace(/\.jsonl$/, ".state.json");
    const tmpPath = statePath + ".tmp";
    const state = {
      lastHash: this.lastHash,
      rotationBoundaryHash: this.rotationBoundaryHash,
      checkpointSequence: this.checkpointSequence,
      totalRecordCount: this.totalRecordCount,
    };
    await fsWriteFile(tmpPath, JSON.stringify(state));
    await rename(tmpPath, statePath);
  }

  private async recoverState(): Promise<"found" | "not_found" | "corrupt"> {
    const statePath = this.path.replace(/\.jsonl$/, ".state.json");
    try {
      const { readFile } = await import("node:fs/promises");
      const raw = await readFile(statePath, "utf-8");
      const state = JSON.parse(raw);
      if (typeof state.lastHash !== "string" || typeof state.checkpointSequence !== "number" ||
          typeof state.rotationBoundaryHash !== "string") {
        return "corrupt";
      }
      this.lastHash = state.lastHash;
      this.rotationBoundaryHash = state.rotationBoundaryHash;
      this.checkpointSequence = state.checkpointSequence ?? 0;
      this.totalRecordCount = state.totalRecordCount ?? 0;
      return "found";
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT") return "not_found";
      return "corrupt";
    }
  }

  async init(opts?: { forceNewChain?: boolean }): Promise<void> {
    const stateResult = await this.recoverState();

    let logExists = false;
    let s;
    try {
      s = await stat(this.path);
      logExists = true;
    } catch {
      logExists = false;
    }

    // Three-way startup:
    // (a) No state file, no log → genuine first run
    if (stateResult === "not_found" && !logExists) {
      this.currentSize = 0;
      return;
    }

    // (c) State file corrupt or exists but unparseable → refuse unless forced
    if (stateResult === "corrupt") {
      if (opts?.forceNewChain) {
        await this.emitChainBreak("state_file_corrupt");
        return;
      }
      throw new Error(
        "[audit-log] state file corrupt or inconsistent. " +
        "Use --force-new-chain to start a new chain (emits a signed chain_break record)."
      );
    }

    // (b) State file present and parseable → base+delta resume
    if (!logExists) {
      this.currentSize = 0;
      return;
    }

    this.currentSize = s!.size;

    if (s!.size > 0) {
      const boundaryHash = stateResult === "found" ? this.rotationBoundaryHash : undefined;
      const fh = await open(this.path, "r");
      try {
        let headBuf = Buffer.alloc(0);
        let offset = 0;
        const chunkSize = 4096;
        const maxFirstLine = 1024 * 1024;
        let firstLine: string | null = null;
        while (offset < s!.size) {
          if (headBuf.length >= maxFirstLine) {
            if (opts?.forceNewChain) {
              await this.emitChainBreak("log_first_record_oversize");
              return;
            }
            throw new Error(
              "[audit-log] first record exceeds 1MB cap (no newline found within limit). " +
              "Use --force-new-chain to start a new chain."
            );
          }
          const readSize = Math.min(chunkSize, s!.size - offset);
          const chunk = Buffer.alloc(readSize);
          await fh.read(chunk, 0, readSize, offset);
          headBuf = Buffer.concat([headBuf, chunk]);
          const text = headBuf.toString("utf-8");
          const nlIdx = text.indexOf("\n");
          if (nlIdx !== -1) {
            firstLine = text.slice(0, nlIdx);
            break;
          }
          offset += readSize;
        }
        if (firstLine === null) {
          const text = headBuf.toString("utf-8").trim();
          if (text.length === 0) {
            if (opts?.forceNewChain) {
              await this.emitChainBreak("log_empty_no_newline");
              return;
            }
            throw new Error(
              "[audit-log] log file exists but contains no parseable content. " +
              "Use --force-new-chain to start a new chain."
            );
          }
          firstLine = text;
        }

        // Parse first record — if it doesn't parse, the log is corrupt
        let firstRecordPrevHash: string | undefined;
        let firstRecordIsBreak = false;
        try {
          const firstRecord = JSON.parse(firstLine);
          if (firstRecord.type === "chain_break") {
            firstRecordIsBreak = true;
            firstRecordPrevHash = firstRecord.priorHead;
          } else {
            firstRecordPrevHash = firstRecord.previousHash;
          }
        } catch {
          if (opts?.forceNewChain) {
            await this.emitChainBreak("log_first_record_corrupt");
            return;
          }
          throw new Error(
            "[audit-log] first record in log is corrupt (unparseable JSON). " +
            "Use --force-new-chain to start a new chain."
          );
        }

        // Read tail: recover chain head and checkpoint state
        const tailSize = Math.min(s!.size, 8192);
        const buf = Buffer.alloc(tailSize);
        await fh.read(buf, 0, tailSize, s!.size - tailSize);
        const tail = buf.toString("utf-8");
        const lines = tail.trimEnd().split("\n");
        let foundLast = false;
        let recordCountFromTail = 0;
        let tailMaxSequence = 0;

        for (let i = lines.length - 1; i >= 0; i--) {
          try {
            const parsed = JSON.parse(lines[i]);
            recordCountFromTail++;

            if (!foundLast) {
              this.lastHash = hashRecord(parsed);
              foundLast = true;
            }

            if (isCheckpoint(parsed)) {
              if (parsed.sequence > tailMaxSequence) {
                tailMaxSequence = parsed.sequence;
              }
            }
          } catch {
            process.stderr.write(
              `[audit-log] warning: corrupt record in tail, skipping\n`,
            );
          }
        }

        if (tailMaxSequence > this.checkpointSequence) {
          this.checkpointSequence = tailMaxSequence;
        }

        if (boundaryHash !== undefined && firstRecordPrevHash !== undefined &&
            firstRecordPrevHash !== boundaryHash) {
          if (opts?.forceNewChain) {
            await this.emitChainBreak("state_log_inconsistent");
            return;
          }
          throw new Error(
            "[audit-log] state file inconsistent with log: first record does not " +
            "chain from rotationBoundaryHash. Use --force-new-chain to start a new chain."
          );
        }

        if (stateResult === "not_found") {
          this.totalRecordCount = recordCountFromTail;
        }
      } finally {
        await fh.close();
      }
    }
  }

  private async emitChainBreak(reason: string): Promise<ChainBreakRecord> {
    const record: ChainBreakRecord = {
      id: `break_${randomUUID()}`,
      type: "chain_break",
      timestamp: new Date().toISOString(),
      reason,
      priorHead: this.lastHash !== "genesis" ? this.lastHash : undefined,
      priorSequence: this.checkpointSequence > 0 ? this.checkpointSequence : undefined,
      priorRecordCount: this.totalRecordCount > 0 ? this.totalRecordCount : undefined,
    };

    record.attestation = await this.signer.sign(record);
    const line = JSON.stringify(record) + "\n";

    await appendFile(this.path, line);
    this.currentSize += Buffer.byteLength(line);

    // Reset chain state — this is a new chain.
    // rotationBoundaryHash is NOT updated: it tracks the file boundary,
    // not the chain boundary. The linkage check compares the first record
    // of a file against rotationBoundaryHash, so mid-file breaks must not
    // overwrite it.
    this.lastHash = hashRecord(record);
    this.checkpointSequence = 0;
    this.totalRecordCount = 0;
    this.recordsSinceCheckpoint = 0;

    await this.persistChainState();
    return record;
  }

  async forceNewChain(reason: string): Promise<ChainBreakRecord> {
    return new Promise((resolve, reject) => {
      this.writeQueue = this.writeQueue.then(async () => {
        try {
          const result = await this.emitChainBreak(reason);
          resolve(result);
        } catch (err) {
          reject(err);
        }
      });
    });
  }
}

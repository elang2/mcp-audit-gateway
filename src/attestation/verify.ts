import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditRecord, CheckpointRecord, ChainBreakRecord, ChainRecord } from "../types.js";
import { isCheckpoint, isChainBreak } from "../types.js";
import { HmacSigner, Ed25519Signer, type Signer } from "./signer.js";
import { hashRecord } from "./audit-log.js";

export interface VerifyResult {
  total: number;
  valid: number;
  invalid: number;
  errors: Array<{ line: number; id: string; reason: string }>;
}

export interface ChainVerifyResult {
  total: number;
  valid: boolean;
  errors: Array<{ line: number; id: string; reason: string }>;
}

export async function verifyAuditLog(
  path: string,
  signer: Signer,
  options?: { verifyChain?: boolean },
): Promise<VerifyResult> {
  const result: VerifyResult = { total: 0, valid: 0, invalid: 0, errors: [] };

  const rl = createInterface({
    input: createReadStream(path),
    crlfDelay: Infinity,
  });

  let lineNum = 0;
  let previousHash: string | null = null;

  for await (const line of rl) {
    lineNum++;
    if (!line.trim()) continue;

    let record: AuditRecord;
    try {
      record = JSON.parse(line);
    } catch {
      result.invalid++;
      result.errors.push({ line: lineNum, id: "?", reason: "invalid JSON" });
      result.total++;
      continue;
    }

    result.total++;
    const signature = record.attestation;
    if (!signature) {
      result.invalid++;
      result.errors.push({ line: lineNum, id: record.id, reason: "missing attestation" });
      continue;
    }

    const recordWithoutSig = { ...record };
    delete recordWithoutSig.attestation;

    const valid = await signer.verify(recordWithoutSig as AuditRecord, signature);
    if (valid) {
      result.valid++;
    } else {
      result.invalid++;
      result.errors.push({ line: lineNum, id: record.id, reason: "signature mismatch" });
    }

    if (options?.verifyChain) {
      if (record.previousHash === undefined) {
        if (valid) {
          result.invalid++;
          result.valid--;
        }
        result.errors.push({
          line: lineNum,
          id: record.id,
          reason: "missing previousHash in chain mode",
        });
      } else {
        const expectedPrevHash = previousHash === null ? "genesis" : previousHash;
        if (record.previousHash !== expectedPrevHash) {
          if (valid) {
            result.invalid++;
            result.valid--;
          }
          result.errors.push({
            line: lineNum,
            id: record.id,
            reason: "chain hash mismatch",
          });
        }
      }
      previousHash = hashRecord(record);
    }
  }

  return result;
}

function getRecordPreviousHash(record: ChainRecord): string | undefined {
  if (isChainBreak(record)) return undefined;
  return (record as AuditRecord | CheckpointRecord).previousHash;
}

export async function verifyChain(records: ChainRecord[]): Promise<ChainVerifyResult> {
  const result: ChainVerifyResult = { total: records.length, valid: true, errors: [] };

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const lineNum = i + 1;

    // chain_break records are valid chain starts (no previousHash required)
    if (isChainBreak(record)) {
      if (i !== 0) {
        result.valid = false;
        result.errors.push({
          line: lineNum,
          id: record.id,
          reason: "chain_break record must be at position 0",
        });
      }
      continue;
    }

    const prevHash = getRecordPreviousHash(record);
    if (i === 0) {
      if (prevHash !== "genesis") {
        result.valid = false;
        result.errors.push({
          line: lineNum,
          id: record.id,
          reason: "first record previousHash must be \"genesis\"",
        });
      }
    } else {
      const prevRecord = records[i - 1];
      const expectedHash = hashRecord(prevRecord);
      if (prevHash !== expectedHash) {
        result.valid = false;
        result.errors.push({
          line: lineNum,
          id: record.id,
          reason: "previousHash does not match hash of prior record",
        });
      }
    }
  }

  return result;
}

export type TruncationFailureCode =
  | "head_missing"
  | "count_mismatch"
  | "sequence_regression";

export interface TruncationCheckResult {
  truncated: boolean;
  lastCheckpoint: CheckpointRecord | null;
  expectedRecordCount: number | null;
  actualRecordCount: number;
  recordCountValid?: boolean;
  absoluteCountVerified?: boolean;
  verificationMode?: "strict" | "relative";
  hasChainBreak?: boolean;
  failureCode?: TruncationFailureCode;
  reason?: string;
}

export interface VerifyCompletenessOptions {
  mode?: "strict" | "relative";
}

export function verifyCompleteness(
  records: ChainRecord[],
  externalCheckpoint: { previousHash: string; sequence: number; recordCount: number },
  options?: VerifyCompletenessOptions,
): TruncationCheckResult {
  const mode = options?.mode ?? "strict";
  const actualRecordCount = records.length;
  let foundCheckpoint: CheckpointRecord | null = null;
  let checkpointIndex = -1;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (isCheckpoint(record)) {
      if (
        record.previousHash === externalCheckpoint.previousHash &&
        record.sequence === externalCheckpoint.sequence &&
        record.recordCount === externalCheckpoint.recordCount
      ) {
        foundCheckpoint = record;
        checkpointIndex = i;
        break;
      }
    }
  }

  if (!foundCheckpoint) {
    let hasDescendant = false;
    for (const record of records) {
      if (isCheckpoint(record) && record.sequence > externalCheckpoint.sequence) {
        hasDescendant = true;
        break;
      }
    }

    if (hasDescendant) {
      // In relative mode: descendant is acceptable, but absolute counts are unverified
      if (mode === "relative") {
        const deltaResult = verifyAdjacentDeltas(records, "relative");
        if (deltaResult) return { ...deltaResult, verificationMode: "relative" };
        return {
          truncated: false,
          lastCheckpoint: null,
          expectedRecordCount: externalCheckpoint.recordCount,
          actualRecordCount,
          absoluteCountVerified: false,
          verificationMode: "relative",
        };
      }
      return {
        truncated: false,
        lastCheckpoint: null,
        expectedRecordCount: externalCheckpoint.recordCount,
        actualRecordCount,
        verificationMode: "strict",
      };
    }

    return {
      truncated: true,
      lastCheckpoint: null,
      expectedRecordCount: externalCheckpoint.recordCount,
      actualRecordCount,
      failureCode: "head_missing",
      verificationMode: mode,
      reason: "externalized checkpoint not found in chain and no descendant checkpoint exists",
    };
  }

  // Check for sequence regression, segmented at chain_break boundaries.
  // A chain_break legitimately resets counters, so monotonicity is only
  // enforced within each segment (between breaks).
  const regressionResult = checkSequenceRegression(records, externalCheckpoint, actualRecordCount, mode);
  if (regressionResult) return regressionResult;

  // Verify recordCount against prefix (strict mode: absolute; relative mode: delta only)
  if (mode === "strict") {
    let nonCheckpointsBefore = 0;
    for (let i = 0; i < checkpointIndex; i++) {
      if (!isCheckpoint(records[i])) nonCheckpointsBefore++;
    }
    const recordCountValid = nonCheckpointsBefore === foundCheckpoint.recordCount;

    if (!recordCountValid) {
      return {
        truncated: true,
        lastCheckpoint: foundCheckpoint,
        expectedRecordCount: externalCheckpoint.recordCount,
        actualRecordCount,
        recordCountValid,
        absoluteCountVerified: true,
        failureCode: "count_mismatch",
        verificationMode: "strict",
        reason: `recordCount mismatch: checkpoint claims ${foundCheckpoint.recordCount} records but ${nonCheckpointsBefore} non-checkpoint records precede it`,
      };
    }
  }

  // Adjacent-pair delta checks (both modes; segment-initial anchor only in strict)
  const deltaResult = verifyAdjacentDeltas(records, mode);
  if (deltaResult) return { ...deltaResult, verificationMode: mode };

  const chainContainsBreak = records.some(isChainBreak);

  return {
    truncated: false,
    lastCheckpoint: foundCheckpoint,
    expectedRecordCount: externalCheckpoint.recordCount,
    actualRecordCount,
    recordCountValid: true,
    absoluteCountVerified: mode === "strict",
    verificationMode: mode,
    hasChainBreak: chainContainsBreak || undefined,
  };
}

/**
 * Check sequence monotonicity, segmented at chain_break boundaries.
 * A chain_break legitimately resets counters, so regression is only
 * flagged within a contiguous segment.
 */
function checkSequenceRegression(
  records: ChainRecord[],
  externalCheckpoint: { previousHash: string; sequence: number; recordCount: number },
  actualRecordCount: number,
  mode: "strict" | "relative",
): TruncationCheckResult | null {
  let segmentCheckpoints: CheckpointRecord[] = [];

  for (const record of records) {
    if (isChainBreak(record)) {
      segmentCheckpoints = [];
      continue;
    }
    if (isCheckpoint(record)) {
      if (segmentCheckpoints.length > 0) {
        const prev = segmentCheckpoints[segmentCheckpoints.length - 1];
        if (record.sequence <= prev.sequence) {
          return {
            truncated: true,
            lastCheckpoint: record,
            expectedRecordCount: externalCheckpoint.recordCount,
            actualRecordCount,
            failureCode: "sequence_regression",
            verificationMode: mode,
            reason: `checkpoint sequence regressed: ${record.sequence} <= ${prev.sequence}`,
          };
        }
      }
      segmentCheckpoints.push(record);
    }
  }

  return null;
}

/**
 * Verify that the recordCount delta between adjacent checkpoints matches
 * the actual number of non-checkpoint records between them.
 * Segmented at chain_break boundaries (delta resets across breaks).
 */
function verifyAdjacentDeltas(records: ChainRecord[], mode?: "strict" | "relative"): TruncationCheckResult | null {
  const checkpoints: { checkpoint: CheckpointRecord; index: number }[] = [];
  // Segment start: index after the most recent chain_break (or 0 if none).
  // No chain_break can occur between same-segment checkpoints — the reset clears the list.
  let segmentStart = 0;

  for (let i = 0; i < records.length; i++) {
    if (isChainBreak(records[i])) {
      checkpoints.length = 0;
      segmentStart = i + 1;
      continue;
    }
    if (isCheckpoint(records[i])) {
      checkpoints.push({ checkpoint: records[i] as CheckpointRecord, index: i });
    }
  }

  // Segment-initial checkpoint absolute anchor (strict mode only — relative mode
  // receives a suffix and can't verify absolute counts).
  if (mode === "strict" && checkpoints.length > 0) {
    const first = checkpoints[0];
    let nonCheckpointsBefore = 0;
    for (let j = segmentStart; j < first.index; j++) {
      if (!isCheckpoint(records[j]) && !isChainBreak(records[j])) nonCheckpointsBefore++;
    }
    if (nonCheckpointsBefore !== first.checkpoint.recordCount) {
      return {
        truncated: true,
        lastCheckpoint: first.checkpoint,
        expectedRecordCount: null,
        actualRecordCount: records.length,
        recordCountValid: false,
        failureCode: "count_mismatch",
        reason: `segment-initial checkpoint claims recordCount ${first.checkpoint.recordCount} but ${nonCheckpointsBefore} non-checkpoint records precede it in segment`,
      };
    }
  }

  for (let i = 1; i < checkpoints.length; i++) {
    const prev = checkpoints[i - 1];
    const curr = checkpoints[i];
    const expectedDelta = curr.checkpoint.recordCount - prev.checkpoint.recordCount;

    let actualNonCheckpoints = 0;
    for (let j = prev.index + 1; j < curr.index; j++) {
      if (!isCheckpoint(records[j])) actualNonCheckpoints++;
    }

    if (actualNonCheckpoints !== expectedDelta) {
      return {
        truncated: true,
        lastCheckpoint: curr.checkpoint,
        expectedRecordCount: null,
        actualRecordCount: records.length,
        recordCountValid: false,
        failureCode: "count_mismatch",
        reason: `adjacent checkpoint delta mismatch: checkpoints ${prev.checkpoint.sequence}->${curr.checkpoint.sequence} claim delta ${expectedDelta} but ${actualNonCheckpoints} non-checkpoint records found between them`,
      };
    }
  }

  return null;
}

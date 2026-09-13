import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditRecord, CheckpointRecord, ChainBreakRecord, ChainRecord, PolicyRule, ToolEntry } from "../types.js";
import { isCheckpoint, isChainBreak } from "../types.js";
import { HmacSigner, Ed25519Signer, type Signer } from "./signer.js";
import { hashRecord } from "./audit-log.js";
import {
  PolicyEngine,
  computeDecisionContextDigest,
  computeDecisionContextDigestV1,
} from "../policy/engine.js";

function hashLine(line: string): string {
  return createHash("sha256").update(line).digest("hex");
}

export interface VerifyResult {
  total: number;
  valid: number;
  invalid: number;
  errors: Array<{ line: number; id: string; reason: string }>;
  /** Present only when {@link verifyAuditLog} was given a `policy`. */
  decisionContext?: DecisionContextSummary;
}

export interface ChainVerifyResult {
  total: number;
  valid: boolean;
  errors: Array<{ line: number; id: string; reason: string }>;
}

/**
 * The policy a verifier holds, independent of the running gateway. Shaped to
 * accept `GatewayConfig["policy"]` directly.
 */
export interface PolicySnapshot {
  defaultEffect: "allow" | "deny";
  rules: PolicyRule[];
}

export type DecisionContextStatus =
  /** Stored digest reproduced from the record plus this policy. */
  | "match"
  /** Record carries no decisionContextDigest; nothing to check. */
  | "absent"
  /** Record lacks a field the context is built from, so no digest can be made. */
  | "unverifiable"
  /** Reproduced under no supported digest version: drift or tampering. */
  | "mismatch";

export interface DecisionContextCheck {
  status: DecisionContextStatus;
  storedDigest?: string;
  /** Recomputation under the current algorithm, present whenever one was made. */
  recomputedDigest?: string;
  /** Which algorithm reproduced the stored digest. Only set on `match`. */
  digestVersion?: "v1" | "v2";
  /** Effect this policy yields for the record. Only set when re-evaluation ran. */
  effect?: "allow" | "deny";
  /** Index into `policy.rules` of the rule that matched, or null for the default. */
  matchedRuleIndex?: number | null;
  /**
   * True when the digest only reproduced under a deny that this policy cannot
   * derive statically, which a rate limit on the matched rule explains.
   */
  rateLimitInferred?: boolean;
  reason?: string;
}

export interface DecisionContextSummary {
  checked: number;
  matched: number;
  mismatched: number;
  unverifiable: number;
  absent: number;
}

/**
 * Recompute a record's `decisionContextDigest` from the record and the policy,
 * and report whether it reproduces.
 *
 * This is what lets a verifier confirm which policy context a decision was made
 * in, rather than taking the gateway's word for the digest. The record supplies
 * `principal`, `toolName`, `namespace` and `upstream`; `matchedRule` and
 * `effect` are not stored on the record at all, so they are recovered by
 * re-running the policy against a reconstructed ToolEntry.
 *
 * A `mismatch` does not distinguish drift from tampering, and cannot: an
 * operator editing a rule and an attacker editing a rule produce the same
 * result. It says the record was not written under the policy given here. Pin
 * the policy alongside the log if you need the stronger claim.
 *
 * Two things this deliberately does not attempt. The digest is only recomputable
 * up to what the policy is a function of, so a rate-limited deny — which depends
 * on the gateway's request counters, runtime state no verifier holds — is
 * admitted as a candidate rather than derived; see `rateLimitInferred`. And
 * `evaluate()` is called on a throwaway engine so this never perturbs a live
 * gateway's counters.
 */
export function verifyDecisionContextDigest(
  record: AuditRecord,
  policy: PolicySnapshot,
): DecisionContextCheck {
  const storedDigest = record.decisionContextDigest;
  if (storedDigest === undefined) {
    return { status: "absent" };
  }

  // toolName is the namespaced form the gateway wrote; namespace and upstream
  // are what the policy matches on. Any of them missing means the context this
  // digest was computed over cannot be rebuilt.
  const missing = (["toolName", "namespace", "upstream"] as const).filter(
    (f) => record[f] === undefined,
  );
  if (missing.length > 0) {
    return {
      status: "unverifiable",
      storedDigest,
      reason: `record is missing ${missing.join(", ")}, so the decision context cannot be rebuilt`,
    };
  }

  const name = record.toolName!;
  const namespace = record.namespace!;
  const prefix = `${namespace}/`;
  const tool: ToolEntry = {
    name,
    // ruleMatches tests the qualified name and the bare upstream name, so both
    // have to be right. registerUpstreamTools builds name as `${namespace}/${originalName}`.
    originalName: name.startsWith(prefix) ? name.slice(prefix.length) : name,
    namespace,
    upstream: record.upstream!,
  };

  const engine = new PolicyEngine(policy.defaultEffect, policy.rules);
  const decision = engine.evaluate(record.principal ?? undefined, tool);
  const ctx = decision.decisionContext;
  const matchedRule = ctx.matchedRule;
  const matchedRuleIndex = matchedRule === null ? null : policy.rules.indexOf(matchedRule);

  // A rate limit can only flip allow to deny, never the reverse, and only on a
  // rule that declares one. That makes the extra candidate a narrow admission
  // rather than a blanket "either effect will do".
  const candidateEffects: Array<"allow" | "deny"> = [ctx.effect];
  if (ctx.effect === "allow" && matchedRule?.rateLimit) {
    candidateEffects.push("deny");
  }

  const versions = [
    { version: "v2" as const, compute: computeDecisionContextDigest },
    { version: "v1" as const, compute: computeDecisionContextDigestV1 },
  ];

  const recomputedDigest = computeDecisionContextDigest({ ...ctx, effect: ctx.effect });

  for (const { version, compute } of versions) {
    for (const effect of candidateEffects) {
      if (compute({ ...ctx, effect }) === storedDigest) {
        return {
          status: "match",
          storedDigest,
          recomputedDigest,
          digestVersion: version,
          effect,
          matchedRuleIndex,
          rateLimitInferred: effect !== ctx.effect ? true : undefined,
        };
      }
    }
  }

  return {
    status: "mismatch",
    storedDigest,
    recomputedDigest,
    effect: ctx.effect,
    matchedRuleIndex,
    reason:
      "decisionContextDigest does not reproduce under this policy: the record was " +
      "written under a different policy, or the record was altered",
  };
}

export async function verifyAuditLog(
  path: string,
  signer: Signer,
  options?: { verifyChain?: boolean; policy?: PolicySnapshot },
): Promise<VerifyResult> {
  const result: VerifyResult = { total: 0, valid: 0, invalid: 0, errors: [] };
  if (options?.policy) {
    result.decisionContext = { checked: 0, matched: 0, mismatched: 0, unverifiable: 0, absent: 0 };
  }

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

    // A record can fail more than one check (chain and decision context, say).
    // Demotion has to be idempotent or the second failure decrements valid a
    // second time and the counts stop summing to total.
    let demoted = !valid;
    const demote = (): void => {
      if (demoted) return;
      demoted = true;
      result.invalid++;
      result.valid--;
    };

    if (options?.verifyChain) {
      if (record.previousHash === undefined) {
        demote();
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
      previousHash = hashLine(line);
    }

    if (options?.policy && result.decisionContext) {
      const summary = result.decisionContext;
      const check = verifyDecisionContextDigest(record, options.policy);
      switch (check.status) {
        case "match":
          summary.checked++;
          summary.matched++;
          break;
        case "mismatch":
          summary.checked++;
          summary.mismatched++;
          demote();
          result.errors.push({ line: lineNum, id: record.id, reason: check.reason! });
          break;
        case "unverifiable":
          // Not demoted. The record carries a digest we cannot rebuild the
          // inputs for, which is a gap in the record, not evidence against it.
          summary.checked++;
          summary.unverifiable++;
          result.errors.push({ line: lineNum, id: record.id, reason: check.reason! });
          break;
        case "absent":
          summary.absent++;
          break;
      }
    }
  }

  return result;
}

function getRecordPreviousHash(record: ChainRecord): string | undefined {
  if (isChainBreak(record)) return undefined;
  return (record as AuditRecord | CheckpointRecord).previousHash;
}

/**
 * Verify chain continuity from raw JSONL lines (octets-first).
 * Hashes stored bytes directly — no parse/re-serialize round-trip.
 */
export async function verifyChainLines(lines: string[]): Promise<ChainVerifyResult> {
  const nonEmpty = lines.filter((l) => l.trim());
  const result: ChainVerifyResult = { total: nonEmpty.length, valid: true, errors: [] };

  for (let i = 0; i < nonEmpty.length; i++) {
    const line = nonEmpty[i];
    const lineNum = i + 1;

    let record: ChainRecord;
    try {
      record = JSON.parse(line);
    } catch {
      result.valid = false;
      result.errors.push({ line: lineNum, id: "?", reason: "invalid JSON" });
      continue;
    }

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
      const expectedHash = hashLine(nonEmpty[i - 1]);
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

/**
 * Verify chain continuity from pre-parsed records.
 * Uses JSON.stringify re-serialization — correct only when insertion-order
 * is preserved (guaranteed in V8/Node.js for integer-free keys).
 *
 * Prefer {@link verifyChainLines} (since 0.7.1) when raw JSONL lines are
 * available. Retained for callers that only have pre-parsed records
 * (e.g. records received as JSON objects over a queue or reconstructed
 * from another storage format rather than raw JSONL lines).
 */
export async function verifyChain(records: ChainRecord[]): Promise<ChainVerifyResult> {
  const result: ChainVerifyResult = { total: records.length, valid: true, errors: [] };

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const lineNum = i + 1;

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

import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditRecord } from "../types.js";
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

export async function verifyChain(records: AuditRecord[]): Promise<ChainVerifyResult> {
  const result: ChainVerifyResult = { total: records.length, valid: true, errors: [] };

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const lineNum = i + 1;

    if (i === 0) {
      if (record.previousHash !== "genesis") {
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
      if (record.previousHash !== expectedHash) {
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

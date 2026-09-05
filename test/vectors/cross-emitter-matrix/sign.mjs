#!/usr/bin/env node
// Cross-emitter matrix — TypeScript/Node.js signer.
// Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
// Uses tuple-array canonical form matching ../verify.mjs.
// Signing key: hex-encoded 32-byte Ed25519 secret from SIGNING_KEY_HEX env var.

import { createHash, generateKeyPairSync, sign as nodeSign, createPrivateKey } from "node:crypto";

const RECORD_FIELD_ORDER = [
  "id", "timestamp", "method", "toolName", "namespace", "upstream",
  "principal", "durationMs", "success", "errorCode", "previousHash",
];

function assertWellFormed(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xD800 && code <= 0xDBFF) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) throw new Error(`unpaired surrogate at ${i}`);
      i++;
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      throw new Error(`unpaired surrogate at ${i}`);
    }
  }
}

function canonicalizeValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") { assertWellFormed(value); return value; }
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`unsafe number ${value}`);
    return value;
  }
  if (Array.isArray(value)) return ["L", value.map(canonicalizeValue)];
  if (typeof value === "object") {
    const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
    return ["M", keys.map((k) => [k, canonicalizeValue(value[k])])];
  }
  throw new Error(`unsupported type ${typeof value}`);
}

function canonicalize(record) {
  const ordered = RECORD_FIELD_ORDER.map((k) => [k, canonicalizeValue(record[k] ?? null)]);
  // Optional nested fields inserted in deterministic order after `previousHash`
  for (const optional of ["decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"]) {
    if (record[optional] != null) {
      ordered.push([optional, canonicalizeValue(record[optional])]);
    }
  }
  return JSON.stringify(ordered);
}

async function runOneShot(privateKey) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const record = JSON.parse(Buffer.concat(chunks).toString("utf-8"));

  const canonical = canonicalize(record);
  const sig = nodeSign(null, Buffer.from(canonical, "utf-8"), privateKey).toString("hex");
  process.stdout.write(JSON.stringify({ canonical, signature_hex: sig }));
}

function writeLineFlushed(line) {
  return new Promise((resolve, reject) => {
    process.stdout.write(line + "\n", (err) => (err ? reject(err) : resolve()));
  });
}

async function runDaemon(privateKey) {
  // Env pinning — only set if missing so we do not override an explicit choice.
  if (!process.env.LC_ALL) process.env.LC_ALL = "C.UTF-8";
  if (!process.env.PYTHONIOENCODING) process.env.PYTHONIOENCODING = "utf-8";

  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line) continue;
    let id = null;
    try {
      const req = JSON.parse(line);
      id = req.id ?? null;
      // privateKey is captured from outer scope and reused across every record —
      // avoiding a PKCS8 parse per line is the reason daemon mode exists.
      const canonical = canonicalize(req.record);
      const sig = nodeSign(null, Buffer.from(canonical, "utf-8"), privateKey).toString("hex");
      await writeLineFlushed(JSON.stringify({ id, ok: true, canonical, signature_hex: sig }));
    } catch (e) {
      try {
        await writeLineFlushed(JSON.stringify({ id, ok: false, error: String(e && e.message ? e.message : e) }));
      } catch (_) {
        // stdout gone; nothing to do — loop terminates on next iteration EOF.
      }
    }
  }
}

async function main() {
  const keyHex = process.env.SIGNING_KEY_HEX;
  if (!keyHex) { console.error("SIGNING_KEY_HEX required"); process.exit(1); }
  const keyDer = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(keyHex, "hex"),
  ]);
  const privateKey = createPrivateKey({ key: keyDer, format: "der", type: "pkcs8" });

  if (process.env.DAEMON_MODE === "1") {
    await runDaemon(privateKey);
  } else {
    await runOneShot(privateKey);
  }
}
main().catch((e) => { console.error(e.message); process.exit(1); });

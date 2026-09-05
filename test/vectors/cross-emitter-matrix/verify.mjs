#!/usr/bin/env node
// Cross-emitter matrix — TypeScript/Node.js verifier.
// Reads {record, signature_hex, public_key_hex} JSON from stdin.
// Locally recomputes canonical form from record, verifies signature against it.
// Writes {verified: bool, local_canonical, sig_hex} to stdout.

import { verify as nodeVerify, createPublicKey } from "node:crypto";

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
  for (const optional of ["decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"]) {
    if (record[optional] != null) {
      ordered.push([optional, canonicalizeValue(record[optional])]);
    }
  }
  return JSON.stringify(ordered);
}

function publicKeyFromHex(publicKeyCache, publicKeyHex) {
  const cached = publicKeyCache.get(publicKeyHex);
  if (cached) return cached;
  const pubDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(publicKeyHex, "hex"),
  ]);
  const publicKey = createPublicKey({ key: pubDer, format: "der", type: "spki" });
  publicKeyCache.set(publicKeyHex, publicKey);
  return publicKey;
}

async function runOneShot() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const { record, signature_hex, public_key_hex } = JSON.parse(Buffer.concat(chunks).toString("utf-8"));

  const pubDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(public_key_hex, "hex"),
  ]);
  const publicKey = createPublicKey({ key: pubDer, format: "der", type: "spki" });

  let localCanonical, verified;
  try {
    localCanonical = canonicalize(record);
    verified = nodeVerify(null, Buffer.from(localCanonical, "utf-8"), publicKey, Buffer.from(signature_hex, "hex"));
  } catch (e) {
    verified = false;
    localCanonical = `ERROR: ${e.message}`;
  }
  process.stdout.write(JSON.stringify({ verified, local_canonical: localCanonical, sig_hex: signature_hex }));
}

function writeLineFlushed(line) {
  return new Promise((resolve, reject) => {
    process.stdout.write(line + "\n", (err) => (err ? reject(err) : resolve()));
  });
}

async function runDaemon() {
  // Env pinning — only set if missing so we do not override an explicit choice.
  if (!process.env.LC_ALL) process.env.LC_ALL = "C.UTF-8";
  if (!process.env.PYTHONIOENCODING) process.env.PYTHONIOENCODING = "utf-8";

  // Cache public keys across records — every driver run reuses the same key,
  // and this avoids a fresh SPKI parse per line.
  const publicKeyCache = new Map();

  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line) continue;
    let id = null;
    try {
      const req = JSON.parse(line);
      id = req.id ?? null;
      const { record, signature_hex, public_key_hex } = req;
      const publicKey = publicKeyFromHex(publicKeyCache, public_key_hex);
      const localCanonical = canonicalize(record);
      const verified = nodeVerify(
        null,
        Buffer.from(localCanonical, "utf-8"),
        publicKey,
        Buffer.from(signature_hex, "hex"),
      );
      await writeLineFlushed(JSON.stringify({ id, ok: true, verified, local_canonical: localCanonical }));
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
  if (process.env.DAEMON_MODE === "1") {
    await runDaemon();
  } else {
    await runOneShot();
  }
}
main().catch((e) => { console.error(e.message); process.exit(1); });

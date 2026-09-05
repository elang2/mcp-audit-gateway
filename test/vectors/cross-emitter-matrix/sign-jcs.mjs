#!/usr/bin/env node
// Cross-emitter matrix — TypeScript/Node.js signer (JCS RFC 8785 variant).
// Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
// Uses RFC 8785 JCS canonical form instead of the tuple-array construction.
//
// JCS library: npm `canonicalize` v4.0.0 (author: Samuel Erdtman, co-author of
// RFC 8785). Package: https://www.npmjs.com/package/canonicalize / source:
// https://github.com/erdtman/canonicalize
//
// Signing key: hex-encoded 32-byte Ed25519 secret from SIGNING_KEY_HEX env var.
// Daemon protocol: DAEMON_MODE=1 → newline-delimited id-envelope requests
// {"id":"<opaque>","record":<object>} on stdin; one JSON response per line on
// stdout — {"id":..., "ok":true, "canonical":..., "signature_hex":...} on
// success, {"id":..., "ok":false, "error":"..."} on failure — one response per
// request line, always. Keeps Node warm across records.

import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { createInterface } from "node:readline";
import canonicalize from "canonicalize";

// Fallback id-extraction regex used only when JSON.parse on the envelope fails,
// so the caller can still correlate the {"ok":false} rejection to its request.
const ID_REGEX = /"id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))/;

function signOne(record, privateKey) {
  // RFC 8785 JCS: sort keys lexicographically at every object level,
  // serialize numbers per ES6 ToString(Number), no insignificant whitespace.
  // The `canonicalize` package returns a JS string; we sign its UTF-8 bytes.
  const canonical = canonicalize(record);
  if (typeof canonical !== "string") {
    throw new Error("canonicalize returned non-string");
  }
  const sig = nodeSign(null, Buffer.from(canonical, "utf-8"), privateKey).toString("hex");
  return { canonical, signature_hex: sig };
}

function extractIdFallback(line) {
  const m = ID_REGEX.exec(line);
  if (!m) return null;
  if (m[1] !== undefined) {
    // Quoted string branch — round-trip through JSON.parse to unescape.
    try { return JSON.parse('"' + m[1] + '"'); } catch { return m[1]; }
  }
  const n = Number(m[2]);
  return Number.isFinite(n) ? n : m[2];
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

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line) continue;
    let id = null;
    try {
      let req;
      try {
        req = JSON.parse(line);
      } catch (parseErr) {
        // Salvage the id via regex so the rejection line still correlates.
        id = extractIdFallback(line);
        throw parseErr;
      }
      id = req.id ?? null;
      // privateKey captured from outer scope, reused across every record —
      // avoiding a PKCS8 parse per line is the reason daemon mode exists.
      const { canonical, signature_hex } = signOne(req.record, privateKey);
      await writeLineFlushed(JSON.stringify({ id, ok: true, canonical, signature_hex }));
    } catch (e) {
      try {
        await writeLineFlushed(JSON.stringify({
          id,
          ok: false,
          error: (e && e.message) ? e.message : String(e),
        }));
      } catch (_) {
        // stdout gone; nothing to do — loop terminates on next iteration EOF.
      }
    }
  }
}

async function runOneShot(privateKey) {
  // One-shot mode: single record on stdin, single JSON object on stdout (no newline).
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const record = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
  process.stdout.write(JSON.stringify(signOne(record, privateKey)));
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

main().catch((e) => { console.error(e && e.message ? e.message : e); process.exit(1); });

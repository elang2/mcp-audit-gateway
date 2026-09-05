#!/usr/bin/env node
// Cross-emitter matrix — DELIBERATELY-BUGGY verifier.
// Simulates an SDK that skips the tuple-array canonical form and uses
// raw JSON.stringify of the record object. Exists to demonstrate that
// the matrix correctly detects SDKs that misimplement canonicalization
// (which is exactly what the 26 documented cross-SDK divergences cause
// in practice).

import { verify as nodeVerify, createPublicKey } from "node:crypto";

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const { record, signature_hex, public_key_hex } = JSON.parse(Buffer.concat(chunks).toString("utf-8"));

  const pubDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(public_key_hex, "hex"),
  ]);
  const publicKey = createPublicKey({ key: pubDer, format: "der", type: "spki" });

  // WRONG CANONICALIZER: uses raw JSON.stringify of the record object.
  // This is what an SDK that skips the tuple-array construction would produce.
  // Compare against the correct canonicalization at ../verify.mjs (tuple-array).
  const wrongCanonical = JSON.stringify(record);

  let verified;
  try {
    verified = nodeVerify(null, Buffer.from(wrongCanonical, "utf-8"), publicKey, Buffer.from(signature_hex, "hex"));
  } catch (e) {
    verified = false;
  }
  process.stdout.write(JSON.stringify({
    verified,
    local_canonical: wrongCanonical,
    sig_hex: signature_hex,
    note: "buggy-verifier: uses JSON.stringify(record) instead of tuple-array canonical form",
  }));
}
main().catch((e) => { console.error(e.message); process.exit(1); });

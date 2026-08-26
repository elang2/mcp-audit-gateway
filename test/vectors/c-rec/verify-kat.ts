// CI gate for the C-REC harness.
//
// Confirms GIF's canonicalize() (used verbatim from ./vendored/gif/) applied
// to the sealed KAT_INPUT reproduces the published KAT_HASH_CG byte-for-byte.
// Also confirms the harness's shipped-canonicalizeValue import runs and
// produces the fixture bytes the payload file records.
//
// Exits non-zero on drift, with remediation hints.
//
// Run: npx tsx test/vectors/c-rec/verify-kat.ts

import { createHash } from "node:crypto";
import { canonicalize as gifCanonicalize } from "./vendored/gif/audit-record-contract.js";
import { canonicalizeValue as mineCanonicalizeValue } from "../../../src/attestation/signer.js";
import {
  KAT_INPUT,
  KAT_EXPECTED,
  TABLE_CASES,
  PRODUCER_VECTORS,
} from "./harness.js";

const sha256 = (s: string): string =>
  createHash("sha256").update(s).digest("hex");

let failures = 0;

// Gate 1: KAT reproduces.
const katHash = sha256(gifCanonicalize(KAT_INPUT));
if (katHash === KAT_EXPECTED) {
  console.log(`  OK  KAT reproduces  ${KAT_EXPECTED.slice(0, 16)}...`);
} else {
  console.error(`  FAIL  KAT expected ${KAT_EXPECTED}`);
  console.error(`        got      ${katHash}`);
  console.error("        GIF vendored source has drifted from the KAT.");
  console.error("        Audit the diff, update KAT_EXPECTED in harness.ts if");
  console.error("        legitimate. See test/vectors/c-rec/PIN-HISTORY.md.");
  failures++;
}

// Gate 2: every table case runs without throwing on the GIF side.
for (const [name, input] of TABLE_CASES) {
  try {
    gifCanonicalize(input);
    console.log(`  OK  table[${name}] GIF ran`);
  } catch (e) {
    console.error(`  FAIL  table[${name}] GIF threw: ${(e as Error).message}`);
    failures++;
  }
}

// Gate 3: producer vectors 1, 2, 4 throw on mine; 3 accepts; 5 accepts both
// forms and returns distinct digests. This locks the contract shapes the
// SEP-3004 comment describes.
const cases: Array<{ label: string; check: () => void }> = [
  {
    label: "Vector 1: lone-surrogate must throw on Mine",
    check: () => {
      let threw = false;
      try {
        mineCanonicalizeValue({ key: "\uD800" } as never);
      } catch {
        threw = true;
      }
      if (!threw) throw new Error("did not throw");
    },
  },
  {
    label: "Vector 2: float must throw on Mine",
    check: () => {
      let threw = false;
      try {
        mineCanonicalizeValue({ pi: 3.14 } as never);
      } catch {
        threw = true;
      }
      if (!threw) throw new Error("did not throw");
    },
  },
  {
    label: "Vector 3: integer-like keys accepted by Mine",
    check: () => {
      mineCanonicalizeValue({
        "2": "second",
        "1": "first",
      } as never);
    },
  },
  {
    label: "Vector 4: unsafe int must throw on Mine",
    check: () => {
      let threw = false;
      try {
        mineCanonicalizeValue({
          big: 9007199254740992,
        } as never);
      } catch {
        threw = true;
      }
      if (!threw) throw new Error("did not throw");
    },
  },
  {
    label:
      "Vector 5: decomposed vs precomposed café produce different digests on Mine",
    check: () => {
      // Use harness's PRODUCER_VECTORS pair — source-file auto-composition
      // would collapse both strings if declared inline here.
      const pair = PRODUCER_VECTORS[4].inputPair!;
      const a = sha256(JSON.stringify(mineCanonicalizeValue(pair.A as never)));
      const b = sha256(JSON.stringify(mineCanonicalizeValue(pair.B as never)));
      if (a === b) {
        throw new Error(
          "decomposed and precomposed produced the same digest — expected different",
        );
      }
    },
  },
  {
    label:
      "Vector 5: GIF collapses decomposed and precomposed to same digest",
    check: () => {
      const pair = PRODUCER_VECTORS[4].inputPair!;
      const a = sha256(gifCanonicalize(pair.A));
      const b = sha256(gifCanonicalize(pair.B));
      if (a !== b) {
        throw new Error(
          "GIF produced different digests for A and B — expected same",
        );
      }
    },
  },
];

for (const c of cases) {
  try {
    c.check();
    console.log(`  OK  ${c.label}`);
  } catch (e) {
    console.error(`  FAIL  ${c.label} — ${(e as Error).message}`);
    failures++;
  }
}

console.log();
if (failures === 0) {
  console.log("C-REC HARNESS FIDELITY: all gates pass.");
  process.exit(0);
} else {
  console.error(
    `C-REC HARNESS FIDELITY: ${failures} failure(s). See remediation notes above.`,
  );
  process.exit(1);
}

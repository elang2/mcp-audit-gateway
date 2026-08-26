// C-REC harness (Canonical Record Equivalence Check).
//
// Runs GIF's canonicalize() (from the vendored source in ./vendored/gif/)
// side-by-side with mcp-audit-gateway's canonicalizeValue (from ../../src/)
// on a fixed set of fixture inputs. Companion to SEP-3004
// (github.com/modelcontextprotocol/modelcontextprotocol/pull/3004).
//
// GIF material is Apache-2.0 (see ./vendored/gif/LICENSE and ./SOURCE.md).
// This harness file itself is MIT-licensed per the repository root LICENSE.
//
// Run:
//   npx tsx test/vectors/c-rec/harness.ts        (prints the markdown table)
//   npm run c-rec:table                          (same, via package script)

import { createHash } from "node:crypto";
import { canonicalize as gifCanonicalize } from "./vendored/gif/audit-record-contract.js";
import { canonicalizeValue as mineCanonicalizeValue } from "../../../src/attestation/signer.js";

const sha256 = (s: string): string =>
  createHash("sha256").update(s).digest("hex");

const mineBytes = (v: unknown): string =>
  JSON.stringify(mineCanonicalizeValue(v as never));

// KAT_INPUT and KAT_EXPECTED are the sealed test-record and its expected
// digest under GIF's canonicalize + sha256, published in the SEP-3004
// discussion. Reproducing the digest byte-for-byte anchors this harness
// to a value both parties can independently verify.
export const KAT_INPUT = {
  event_id: "99999999-9999-9999-9999-999999999999",
  event_type: "tool_call",
  extensions: {
    "caller-governance": {
      flagged: false,
      invoked_by_principal_id: null,
      purpose_declared: "reconcile June invoices",
      session_id: "55555555-5555-5555-5555-555555555555",
    },
  },
  occurred_at: "2026-06-06T12:00:00.000Z",
  outcome: "deferred",
  previous_hash: null,
  principal_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  tool_name: "export",
} as const;

export const KAT_EXPECTED =
  "d494769c1ae442ea88dd190068747abf63c0568a3b856f85791b1a50a99d48b4";

// 11-row side-by-side fixture set.
export const TABLE_CASES: [string, unknown][] = [
  ["Simple, keys already sorted", { a: 1, b: 2 }],
  ["Keys need sorting (b before a)", { b: 1, a: 2 }],
  ["Nested object", { outer: { z: 1, a: 2 } }],
  ["Array of scalars", { list: [3, 1, 2] }],
  ["Boolean + null", { flag: true, missing: null }],
  ["Unicode key (single codepoint)", { "café": "value" }],
  ["Empty object", {}],
  ["Empty array", { arr: [] }],
  ["String with special chars", { s: 'a"b\\c' }],
  ["Nested extensions-style", {
    core: "v",
    extensions: {
      "caller-governance": { session_id: "abc", purpose_declared: "test" },
    },
  }],
  // Astral-plane key-ordering: BMP private-use U+E000 vs grinning face
  // U+1F600. UTF-16 code-unit order and Unicode-codepoint order disagree.
  // Both canonicalizers use Array.prototype.sort() default (UTF-16 code
  // unit) so both produce the same key order; a codepoint-sorting
  // reimplementation (Python's default sorted()) would not.
  ["Astral-plane key ordering (U+1F600 vs U+E000)", {
    "\u{E000}": "bmp-private",
    "\u{1F600}": "grinning",
  }],
];

// Five producer-requirement vectors: fixture inputs that a
// canonicalization contract has to state producer requirements about (or
// accept and paper over in prose). Named in the SEP-3004 discussion.
export const PRODUCER_VECTORS: Array<{
  label: string;
  inputDescr: string;
  input?: unknown;
  inputPair?: { A: unknown; B: unknown };
}> = [
  {
    label: "Lone-surrogate string value",
    inputDescr: '{"key":"\\uD800"}   // unpaired high surrogate',
    input: { key: "\uD800" },
  },
  {
    label: "Float / non-integer number",
    inputDescr: '{"pi":3.14}',
    input: { pi: 3.14 },
  },
  {
    label: "Integer-like top-level key",
    inputDescr: '{"2":"second","1":"first","b":"beta","a":"alpha"}',
    input: { "2": "second", "1": "first", "b": "beta", "a": "alpha" },
  },
  {
    label: "Unsafe integer (2^53)",
    inputDescr:
      '{"big":9007199254740992}   // Number.MAX_SAFE_INTEGER + 1',
    input: { big: 9007199254740992 },
  },
  {
    // Decomposed vs precomposed café. GIF's normalizeString applies NFC
    // (plus control-char rejection + ASCII-space trim + length cap
    // MAX_FIELD_LEN=8192), so both inputs collapse to the same digest.
    // Mine applies no Unicode normalization; the two inputs produce
    // different digests. The NFC boundary as a fixture rather than as
    // prose.
    label: "Decomposed vs precomposed cafe (NFC boundary)",
    inputDescr:
      'A: {"key":"cafe\\u0301"}    // decomposed (5 codepoints)\n' +
      '       B: {"key":"caf\\u00e9"}       // precomposed (4 codepoints)',
    inputPair: {
      // Explicit escapes to force byte-level distinction. Source-file
      // auto-composition on save would otherwise collapse both to the same
      // string, defeating the fixture's purpose.
      A: { key: "café" },
      B: { key: "café" },
    },
  },
];

function tryBytes(fn: () => string): { kind: "bytes" | "throws"; value: string } {
  try {
    return { kind: "bytes", value: fn() };
  } catch (e) {
    return { kind: "throws", value: (e as Error).message };
  }
}

export function buildTableSection(): string {
  const lines: string[] = [];
  lines.push("## Side-by-side comparison");
  lines.push("");
  lines.push(
    "| # | Case | GIF sorted-JSON | Mine (type-tagged M/L) | GIF sha256[:12] | Mine sha256[:12] |",
  );
  lines.push(
    "|---|------|-----------------|------------------------|-----------------|-------------------|",
  );
  for (let i = 0; i < TABLE_CASES.length; i++) {
    const [name, input] = TABLE_CASES[i];
    const gifOut = tryBytes(() => gifCanonicalize(input));
    const mineOut = tryBytes(() => mineBytes(input));
    const gifCell =
      gifOut.kind === "bytes" ? gifOut.value : `<throws: ${gifOut.value}>`;
    const mineCell =
      mineOut.kind === "bytes" ? mineOut.value : `<throws: ${mineOut.value}>`;
    const gifSha =
      gifOut.kind === "bytes" ? sha256(gifOut.value).slice(0, 12) : "-";
    const mineSha =
      mineOut.kind === "bytes" ? sha256(mineOut.value).slice(0, 12) : "-";
    lines.push(
      `| ${i + 1} | ${name} | \`${gifCell.replace(/\|/g, "\\|")}\` | ` +
        `\`${mineCell.replace(/\|/g, "\\|")}\` | \`${gifSha}\` | \`${mineSha}\` |`,
    );
  }
  return lines.join("\n");
}

export function buildVectorSection(): string {
  const lines: string[] = [];
  lines.push("## Five producer-requirement vectors");
  lines.push("");
  lines.push(
    "Fixture inputs a canonicalization contract has to state producer " +
      "requirements about (or accept and paper over in prose). Vectors 1-4 " +
      "are single-input cases (lone-surrogate string, float, integer-like " +
      "top-level key, unsafe integer). Vector 5 is a pair (decomposed vs " +
      "precomposed cafe) that surfaces the NFC-normalization boundary " +
      "explicitly.",
  );
  lines.push("");
  for (let i = 0; i < PRODUCER_VECTORS.length; i++) {
    const v = PRODUCER_VECTORS[i];
    lines.push(`### Vector ${i + 1}: ${v.label}`);
    lines.push("");
    lines.push("```");
    lines.push(`input: ${v.inputDescr}`);
    if (v.inputPair) {
      const gA = tryBytes(() => gifCanonicalize(v.inputPair!.A));
      const gB = tryBytes(() => gifCanonicalize(v.inputPair!.B));
      const mA = tryBytes(() => mineBytes(v.inputPair!.A));
      const mB = tryBytes(() => mineBytes(v.inputPair!.B));
      const same = (a: typeof gA, b: typeof gB): string =>
        a.kind === "bytes" && b.kind === "bytes" && a.value === b.value
          ? "YES"
          : "NO";
      lines.push(renderPairLine("GIF   A", gA));
      lines.push(renderPairLine("GIF   B", gB));
      lines.push(
        `GIF   same digest for A and B? ${same(gA, gB)}` +
          (same(gA, gB) === "YES"
            ? " (NFC applied inside canonicalize)"
            : ""),
      );
      lines.push(renderPairLine("Mine  A", mA));
      lines.push(renderPairLine("Mine  B", mB));
      lines.push(
        `Mine  same digest for A and B? ${same(mA, mB)}` +
          (same(mA, mB) === "NO"
            ? " (no normalization applied; A and B are distinct byte sequences)"
            : ""),
      );
    } else {
      const gif = tryBytes(() => gifCanonicalize(v.input));
      const mine = tryBytes(() => mineBytes(v.input));
      lines.push(renderSingleLine("GIF", gif));
      lines.push(renderSingleLine("Mine", mine));
    }
    lines.push("```");
    lines.push("");
  }
  return lines.join("\n");
}

function renderSingleLine(
  prefix: string,
  r: { kind: "bytes" | "throws"; value: string },
): string {
  if (r.kind === "bytes") {
    return `${prefix}:  bytes = ${r.value}  sha256 = ${sha256(r.value).slice(0, 16)}...`;
  }
  return `${prefix}:  throws  ("${r.value}")`;
}

function renderPairLine(
  prefix: string,
  r: { kind: "bytes" | "throws"; value: string },
): string {
  if (r.kind === "bytes") {
    return `${prefix}: bytes = ${r.value}  sha256 = ${sha256(r.value).slice(0, 16)}...`;
  }
  return `${prefix}: throws  ("${r.value}")`;
}

// Direct-run behavior: print KAT check + table.
if (import.meta.url === `file://${process.argv[1]}`) {
  const katOut = sha256(gifCanonicalize(KAT_INPUT));
  console.log("### KAT verification");
  console.log(`  gif sha256:   ${katOut}`);
  console.log(`  KAT_EXPECTED: ${KAT_EXPECTED}`);
  console.log(`  match:        ${katOut === KAT_EXPECTED ? "YES" : "NO"}`);
  if (katOut !== KAT_EXPECTED) {
    console.error(
      "KAT MISMATCH — GIF vendored source or the KAT expected value has drifted.",
    );
    process.exit(1);
  }
  console.log();
  console.log(buildTableSection());
  console.log();
  console.log(buildVectorSection());
}

export { sha256 };

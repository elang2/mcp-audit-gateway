# Changelog

## [Unreleased]

### Added

- `verifyDecisionContextDigest(record, policy)` in `src/attestation/verify.ts`, and a `policy` option on `verifyAuditLog(path, signer, { policy })`. Before this, `verify.ts` contained **zero** occurrences of `decisionContextDigest`: the gateway stamped the digest onto every record it emitted, and no verifier ever recomputed it. A record could carry a digest belonging to an entirely different policy context and pass verification, because the digest was covered by the signature as an opaque field value and by nothing else. The new function rebuilds the `DecisionContext` from the record's `principal`, `toolName`, `namespace` and `upstream`, recovers `matchedRule` and `effect` — neither of which is stored on the record — by re-running `PolicyEngine.evaluate()` against the supplied policy, and reports `match`, `mismatch`, `unverifiable` or `absent`.
- A stable `computeDecisionContextDigest`. The digest is now `sha256(JSON.stringify(["DecisionContext/v2", canonicalizeValue(dropNullMembers(ordered))]))`, following the `PROJECTION_DOMAIN_TAG` idiom already used by `attestation/witness.ts` so a decision-context digest cannot collide with a record hash or a witness projection on identical inner content.
- `computeDecisionContextDigestV1`, the previous implementation preserved verbatim and exported. `verifyDecisionContextDigest` tries v2 then v1 and reports which one reproduced in `digestVersion`, so records written by 0.8.2 and earlier still verify.
- 23 cases in `src/attestation/verify-decision-context.test.ts`. Nine of them assert on records produced by a real `Gateway.handleToolsCall` denial rather than hand-built contexts, since a hand-built context tests the test's idea of the decision context rather than the gateway's.

### Rationale

- **Why the verify side was never implemented: the digest was not reproducible.** v1 hashed `JSON.stringify` of an array holding the raw `matchedRule` object, and `JSON.stringify` emits object keys in insertion order. Measured on v1: the rule `{effect, principals, tools}` and the same rule spelled `{tools, principals, effect}` produce different digests. Reproduction therefore depended on the key insertion order of an in-memory object that no longer exists by the time anyone verifies, so a verifier holding the record and the policy could not reliably recompute the value. The fix is to the property, not the symptom — routing the context through `canonicalizeValue` makes key order and `undefined` members irrelevant, which is what makes recomputation possible at all.
- `dropNullMembers` additionally folds explicit-null optionals together with absent ones. `canonicalizeValue` drops `undefined` members but keeps `null` ones, and for a `PolicyRule` that distinction carries no meaning: every optional is read as falsy-or-present (`rule.principals && length > 0`, `rule.rateLimit`, `limit.maxPerMinute != null`), so `{effect, rateLimit: null}` and `{effect}` describe the same rule and now digest alike. It is applied to the whole ordered tuple list, not just the rule; the tuples are arrays, so `["principal", null]` keeps its null and an anonymous principal stays distinguishable from a named one.
- **A `mismatch` cannot separate drift from tampering, and does not claim to.** An operator editing a rule and an attacker editing a rule produce the same result. The finding is that the record was not written under the policy supplied here; the stronger claim requires pinning the policy alongside the log.
- **The digest is only recomputable up to what the policy is a function of.** A rate-limited deny depends on the gateway's request counters, runtime state no verifier holds, so it is admitted as a candidate rather than derived and flagged in `rateLimitInferred`. The admission is narrow rather than "either effect will do": a rate limit can only flip allow to deny, never the reverse, and only on a rule that declares one, so the opposite-effect candidate is gated on both conditions. Asserted in both directions — a record claiming a deny over a rule with no `rateLimit`, rule held byte-identical so only the effect differs, is a `mismatch`.
- `originalName` is derived by stripping the `${namespace}/` prefix, because `ruleMatches` tests the qualified name *and* `tool.originalName` while the record only stores the qualified form. A policy may legitimately name a tool without its namespace; without the derivation such a rule never matches and the recomputed context silently becomes the default-effect one. Covered by a dedicated case using a bare-name rule.
- `evaluate()` runs on a throwaway `PolicyEngine`, so verification never perturbs a live gateway's rate-limit counters. Asserted by checking the same record five times against a 1-per-minute rule and requiring the same verdict each time.
- `unverifiable` deliberately does not demote a record. A record carrying a digest whose inputs cannot be rebuilt is a gap in the record, not evidence against it; it is reported in `errors` and counted, but the signature verdict stands.
- Mutation-tested rather than assumed: nine mutants across the digest and the verifier (dropping canonicalization, dropping the null-folding, dropping the `originalName` derivation, ignoring the record principal, ungating the effect flip, removing each demotion, and adding a wrong one) were each injected and reverted. All nine fail at least one case. The ungated-effect-flip mutant initially **survived** — the negative assertion had changed the rule as well as the effect, so the rule difference alone produced the mismatch and the effect gate was never the deciding factor. Replaced with a case holding the rule identical.

### Changed

- New records carry v2 digests, which differ byte-for-byte from v1 for the same context. This does not invalidate any existing signature: the digest is an opaque string field covered by `canonicalizeRecord` like any other, and stored values are untouched. The 46 checkpoint vectors, 46 Python vectors and 51 APS vectors all still pass, confirming the change is isolated to the decision-context digest and does not reach record canonicalization.
- `VerifyResult` gains an optional `decisionContext` summary (`checked`/`matched`/`mismatched`/`unverifiable`/`absent`), populated only when a `policy` is supplied. Default behaviour of `verifyAuditLog` is unchanged.

### Fixed

- Record demotion inside `verifyAuditLog` is now idempotent. This is a precondition introduced by this change rather than a pre-existing bug: the two chain-mode failure branches are mutually exclusive per record, so nothing could double-decrement before. Adding a third failure source made it reachable — a record failing both the chain check and the digest check would have run `result.valid--` twice and `valid + invalid` would no longer sum to `total`. Asserted directly.

## [0.8.2] - 2026-09-10

### Added

- Five cases added to `src/attestation/verify-audit-log-chain-mode.test.ts`, bringing that file to eight adversarial cases plus a clean-log baseline on `verifyAuditLog(path, signer, { verifyChain: true })`, the shipping path invoked by `cli.ts`. **Three of the file's reject cases are not new here.** Content tamper, delete and reorder landed in [`0d9f0d5`](https://github.com/elang2/mcp-audit-gateway/commit/0d9f0d5) on 2026-09-05, reached `main`, and were never carried by a tagged release, so v0.8.1 and earlier do not contain the file at all. v0.8.2 adds the fourth tamper class, a fabricated record inserted between two existing records, plus the four shape cases below.
- Coverage history for the record. At v0.7.8, the tag under review when the gap was raised, the only test-side caller passing `{ verifyChain: true }` was a clean-log restart assertion in `bugfix.test.ts`, with no reject case on that path. Raised as `modelcontextprotocol/modelcontextprotocol#3004` (issuecomment-5523985337).
- Four cases pinning the shape of insertion detection rather than only its occurrence. The two-invalid-records count for a mid-sequence insertion is asserted at tail lengths 4, 20 and 60, since it is invariant in tail length. A tail insertion is asserted to mark one record invalid, not two, so the stronger claim cannot be over-generalised. An inserted record carrying no `attestation` is asserted to leave the chain intact downstream. And a tail insert carrying a **correct** `previousHash` is asserted to be caught by the signature check alone, with zero chain-hash mismatches — `hashLine` is a bare SHA-256 over the stored line and takes no secret, so an attacker can always compute a valid link. At the tail specifically, that is the case chain mode cannot catch by itself: measured, a correctly-linked insert at the tail yields one signature error and zero chain-hash mismatches, while the same insert mid-sequence still desyncs the successor and yields two errors. So the blind spot is positional, and an error count bounds detection rather than compromise.

### Rationale

- The shipping CLI path and the records-based path assert the same property (append-only chain integrity) but diverge at the hash input: the CLI path hashes stored JSONL bytes via `hashLine`, the records-based path re-serializes the parsed record. The insert case additionally pins the two distinct chain-hash failure modes it produces, the fabricated record's own genesis-vs-rolling mismatch and the immediate successor's stale `previousHash`, by line number.
- Records downstream of the successor re-sync because the rolling hash advances past them unchanged, so a mid-sequence insertion marks exactly two records invalid at any tail length. That advance is not unconditional, because the unparseable-JSON and missing-attestation branches `continue` before reaching it (`verify.ts:52` and `:60`; the advance is `verify.ts:99`). An inserted record with no `attestation` is therefore flagged for the missing attestation and leaves every later chain check green. It is detected, but not as a chain break, which is a design property of chain mode rather than a coverage gap, and it is asserted rather than noted.

### Fixed

- Corrected the header comment in `verify-audit-log-chain-mode.test.ts`, which described `chain.test.ts` as carrying four tamper cases. It carries three (delete, reorder, insert); the remaining `it()` block is the happy path, and it is the first in the file.

### Note

- `package.json` was not bumped for the `v0.8.1` tag and still read `0.8.0` at that tag. This release sets it to `0.8.2` directly. Versions between tags and the manifest are aligned again from here.

## [0.8.1] - 2026-08-29

Docs only, no version bump at the time. Expanded `SECURITY-DESIGN.md` and consolidated docs and code comments (`c249973`). No `src/` behaviour change. Recorded here because the tag existed with no CHANGELOG section, which made `[0.8.2]` appear to follow `[0.8.0]` directly.

## [0.8.0] - 2026-08-26

### Added

- Witness projection: a deterministic role/party-scoped projection of an `AuditRecord`. New exports from `src/attestation/witness.ts` (also re-exported from the package entry):
  - `projectByRole(record, role, party?)`: returns a `WitnessProjection` covering only the fields attributed to the named role (optionally further refined by party). Distinct type from `AuditRecord`.
  - `projectionDigest(projection)`: deterministic canonical digest of a projection, domain-tagged so it cannot collide with a record digest by construction (records serialize as `{...}`; projections wrap as `[TAG, canonical]` starting with `[`). Reuses the shipped `canonicalizeValue` for the value canonicalization; adds an outer `[TAG, canonical]` array wrap serialized via `JSON.stringify` for domain separation from records. Cross-language re-implementers must replicate both. Non-integer numbers, unsafe integers, and lone surrogates in projected fields all throw. This is the same producer requirement Vector 2 of the C-REC harness enforces on records.
  - `rolesInRecord(record)`, `partiesForRole(record, role)`, `scopeForRoleAndParty(record, role, party?)`: enumerate the `parties[]` axis. All three filter out entries with unknown role values (defensive against untrusted JSON input).
  - `PROJECTION_DOMAIN_TAG`: exported constant so consumers can verify the domain tag without hardcoding.
- `WitnessProjection` interface with mandatory type discriminant (`"witness-projection"`), `projectionOf` hash (points back to the source record via `hashRecord`), `role`, optional `party`, `scope`, and `fields`.
- Tests at `src/attestation/witness.test.ts` covering: cross-scope leakage prevention, determinism, domain-separation negative (projection digest never equals any record digest), role-vs-party axis distinction, the reduction-preserves-scope pattern as an executable check, and runtime robustness (float `durationMs`, unknown role values in untrusted input, dotted-path scope entries currently returning undefined).

### Rationale

- The `parties[]` array shipped in v0.2.0 encodes multi-party attribution but consumers can silently collapse the witness/asserter distinction when aggregating. `projectByRole` is the read-side primitive consumers call to preserve scope boundaries under aggregation. It doesn't enforce use; nothing at the language level prevents a consumer from iterating `record.parties[]` directly. The primitive makes the scope-preserving path callable in a single line.
- Design shape (distinct type + domain-tagged digest) was chosen over a nulled `AuditRecord` after adversarial review. A nulled record is type-indistinguishable from a legitimate partial record, which invites accidental rehash-as-record and cross-domain digest collision.
- Projection is lossy for out-of-scope fields; in-scope fields are preserved verbatim in `fields`. `projectionOf` is the pointer back to the source record for cases requiring the full record.
- Role-primary API with optional party refinement supports two consumer axes: role-level safety (as needed for e.g. the [SEP-2817](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2817) parties/witness discussion) and party-level field attribution (as needed for e.g. [CycloneDX/specification#1016](https://github.com/CycloneDX/specification/issues/1016) field-mapping approaches).
- Field paths in `scope` are treated as top-level record keys. Dotted-path (nested-field) support is a follow-up if consumers need it; the current behavior returns `undefined` for dotted entries and is locked by test.

### Downstream

- Write-side regression tests at [commit `a87b09b`](https://github.com/elang2/mcp-audit-gateway/commit/a87b09b) assert scope arrays don't overlap and no cross-scope leakage on record ingest. `projectByRole` is the read-side primitive that consumes those record shapes to preserve the boundary under aggregation.
- Verifiers in the shape of CycloneDX #1016's field-mapping approach can call `projectionDigest` to compute a scope-bounded digest independently from the record's own digest.

## [0.7.8] - 2026-08-26

### Added

- Canonical Record Equivalence Check (C-REC) side-by-side harness at `test/vectors/c-rec/`. Companion to SEP-3004 ([modelcontextprotocol/modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)). Runs the same input through GIF's sorted-JSON `canonicalize()` (used VERBATIM from vendored source, not reimplemented) and this repo's type-tagged M/L `canonicalizeValue`, showing byte-level divergence and SHA-256 digests. Test infrastructure only.
- `test/vectors/c-rec/vendored/gif/audit-record-contract.ts`: [notboatanchor/gif](https://github.com/notboatanchor/gif) @ `e1f02a95506e81e7766c3ba3a684ecad7cfff12f` vendored byte-for-byte (14602 bytes, sha256 `ed4e75adecd71a6e6ec504b1ffb1b7d762c737e80515476bc76672fddbd46a77`). SPDX header, copyright header, Apache-2.0 licensing preserved. No modifications.
- `test/vectors/c-rec/vendored/gif/LICENSE` and `NOTICE`: reproduced verbatim from upstream per Apache-2.0 §4(a) and §4(d).
- `test/vectors/c-rec/SOURCE.md`: full provenance documentation. Apache-2.0 attribution, verification hash, notes on the KAT constants.
- `test/vectors/c-rec/harness.ts`: imports `canonicalize` from the vendored file and `canonicalizeValue` from `src/attestation/signer.ts`. Defines KAT anchor, 11-row side-by-side fixture set, and five producer-requirement vectors (lone-surrogate, float, integer-like key, unsafe integer, decomposed vs precomposed café).
- `test/vectors/c-rec/verify-kat.ts`: CI gate. Confirms GIF's vendored `canonicalize()` reproduces `KAT_HASH_CG` byte-for-byte and locks the accept/throw contract for each producer vector.
- `test/vectors/c-rec/reports/build-comment-payload.ts`: generates a markdown payload for the SEP-3004 PR comment to reference at a tag URL.
- `test/vectors/c-rec/reports/SEP-3004-comment-payload.md`: committed generated output.
- `test/vectors/c-rec/PIN-HISTORY.md`: audit trail of GIF pin changes. Seeded with `e1f02a9` initial pin.
- `test/vectors/c-rec/README.md`: harness documentation, CI-gate description, pin-update procedure.
- npm scripts: `c-rec:verify` runs the KAT + contract gates via tsx; `c-rec:table` prints the side-by-side to stdout; `c-rec:report` regenerates the payload; `c-rec:report:check` verifies committed payload is byte-identical to a fresh regen.
- CI: the `vectors:` job in `.github/workflows/ci.yml` runs `c-rec:verify` and `c-rec:report:check` on every push. Merges fail on drift.

### Rationale

- Uses GIF verbatim rather than reimplementing. Vendoring cleanly satisfies Apache-2.0 §4 attribution (SPDX + copyright + NOTICE all preserved and reproduced) without derivative-work reasoning. The comparison in every payload row is between GIF's actual bytes and this repo's actual bytes; no translation layer sits between the two.

## [0.7.1] - 2026-08-25

### Added

- Equivalence test: `verifyChain` and `verifyChainLines` agree on writer-emitted records, pinning the invariant that both paths converge for records this codebase produces.
- Divergence test: on foreign records with integer-like top-level keys, `verifyChainLines` passes while `verifyChain` reports a chain mismatch — per ECMA-262 §10.1.11.1 (OrdinaryOwnPropertyKeys), integer-indexed properties enumerate before string keys, so `JSON.stringify(JSON.parse(line))` produces different bytes than the stored line. Fixture is hand-crafted JSONL that bypasses the writer; the current `AuditRecord` interface admits no place for such keys, so this pins receiver-side behavior on shapes another implementation could emit.

### Changed

- `verifyChain` JSDoc strengthened with a "Prefer `verifyChainLines` (since 0.7.1)" note and a broader retention rationale covering records received as JSON objects rather than raw JSONL lines. No `@deprecated` tag — the boundary is enforced by the equivalence and divergence tests above, not by a removal-path marker on a function that has legitimate current callers.

## [0.7.0] - 2026-08-24

### Changed

- Chain continuity verification now hashes raw stored line bytes (octets-first) instead of re-serializing parsed JSON. Eliminates cross-language round-trip fragility where `JSON.stringify(JSON.parse(line))` may not reproduce original bytes.

### Added

- `verifyChainLines(lines: string[])`: new primary API for octets-based chain verification. Hashes stored bytes directly with no parse/re-serialize step.
- `verifyChain(records)` and `verifyChainLines(lines)` now both exported from package index.
- SECURITY-DESIGN.md: new "Dual-Path Verification Architecture" section documenting the separation between chain continuity (octets) and signature verification (canonical form).

### Fixed

- `verifyAuditLog` with `verifyChain: true` previously used `hashRecord()` (re-serialization) for chain hash computation. Now uses raw line bytes, matching how the producer computed `previousHash`.

## [0.2.0] - 2026-08-22

### Added

- Multi-party attribution: each audit record now declares which entity (gateway, policy-engine) witnessed or asserted which fields via the `parties` array
- `decisionContextDigest` field: SHA-256 digest of the policy evaluation context, linking audit records to specific policy decisions
- Conformance test vectors: 17 vectors covering canonicalization (8), hash chain (3), and party attribution (6)
- Cross-language verifiers: JavaScript (`test/vectors/verify.mjs`) and Python (`test/vectors/verify.py`) both pass all 17 vectors byte-identical
- `.well-known/agent-governance.json`: machine-readable governance declaration implementing the OpenSSF SIEP-171 pattern
- Edge-case vectors for party attribution: empty array vs null, scope ordering significance, chain continuity with parties

### Changed

- Canonical form now conditionally includes `decisionContextDigest` at position 10 and `parties` at the end when present
- Backward-compatible: records without these fields produce identical canonical hashes to v0.1.0

## [0.1.0] - 2026-08-16

### Added

- Initial release
- Transparent MCP proxy with `mcp-audit wrap` CLI
- HMAC-SHA256 and Ed25519 attestation signing
- SHA-256 hash-chained audit log (JSONL)
- Full gateway mode with multi-upstream routing and tool namespacing
- OPA-style policy engine with glob-based ACLs and per-principal rate limits
- OpenTelemetry traces and metrics export
- Chain verification CLI (`mcp-audit verify`)
- Live tail CLI (`mcp-audit tail`)
- Key generation CLI (`mcp-audit keygen`)

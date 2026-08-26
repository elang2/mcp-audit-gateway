# Changelog

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

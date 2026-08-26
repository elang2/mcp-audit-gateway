# Changelog

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

# Changelog

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

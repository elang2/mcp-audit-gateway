# Security Design

This document describes the security invariants of the attestation and checkpoint subsystem, the threat model they address, and the pitfalls discovered during adversarial design review.

## Threat Model

The attestation layer defends against three classes of attack on audit logs:

1. **Truncation**: an operator or compromised process deletes records from the tail of a log file to hide evidence of tool calls.
2. **Tampering**: modification of individual records (field values, ordering, or removal) after they are written.
3. **Planted state**: an attacker with filesystem access fabricates or replays the `.state.json` file to make the system resume from a false position, enabling silent truncation of the real log.

The system does NOT defend against an attacker who holds the signing key AND has write access to both log and state files simultaneously. At that point, the attacker can forge new valid records. Key management (KMS, HSM, or envelope encryption) is the defense for that layer.

## Security Properties

| # | Property | Mechanism | Round Introduced |
|---|----------|-----------|-----------------|
| 1 | Injective canonical form | Type-tagged containers: objects become `["M", pairs]`, arrays become `["L", values]` | Round 3 |
| 2 | Cross-language sort equivalence | UTF-16 code-unit sort order; Python uses `key.encode("utf-16-be")` | Round 4 |
| 3 | Unpaired surrogate rejection | `assertWellFormedString` at all four canonicalization entry points | Rounds 4-5 |
| 4 | Hash chain continuity across rotation | `rotationBoundaryHash` persisted at rotation; first record of new file chains from it | Round 5 |
| 5 | Planted state detection | Exact linkage check: first record's `previousHash` must equal `rotationBoundaryHash` in state file | Round 5 |
| 6 | No false-positive after chain break | `rotationBoundaryHash` is separate from `lastHash`; only `persistState()` (rotation) updates it | Round 5 |
| 7 | Fail-closed on corrupt input | Unparseable first line, oversized first line, and empty log all refuse to start | Rounds 5-6 |
| 8 | Segmented monotonicity | Checkpoint sequence regression checked per-segment; `chain_break` resets the segment | Round 3 |
| 9 | Segment-initial absolute anchor | First checkpoint in each segment verified against actual record count (strict mode) | Round 4 |
| 10 | Memory-bounded init | Grow-to-newline capped at 1MB; exceeding cap treated as corrupt | Round 6 |

## Canonical Form Specification

### Record Types

Three record types exist, each with a fixed canonical field ordering:

**AuditRecord**: `[id, timestamp, method, toolName, namespace, upstream, principal, durationMs, success, errorCode, previousHash]` with optional fields (`decisionContextDigest`, `extensionsDigest`, `parties`) inserted at defined positions when present.

**CheckpointRecord**: `[id, type="checkpoint", timestamp, sequence, recordCount, previousHash]` with optional `parties`.

**ChainBreakRecord**: `[id, type="chain_break", timestamp, reason, priorHead, priorSequence, priorRecordCount]`.

### canonicalizeValue (for extensions and arbitrary nested data)

Recursively transforms a value into its canonical representation:

- `null` and `undefined` map to `null`
- Strings pass through after surrogate validation
- Booleans pass through
- Numbers must be safe integers (floats and unsafe integers throw)
- Arrays become `["L", [canonicalized elements...]]`
- Objects become `["M", [[key, canonicalized value]...]]` with keys sorted by UTF-16 code-unit order, undefined-valued keys dropped

The type tags make the mapping injective: `{a: 1}` and `[["a", 1]]` produce distinct canonical forms because the object gets `["M", ...]` wrapping while the array gets `["L", ...]` wrapping. A bare two-element array cannot appear at any position where a value is expected.

### String Well-Formedness

All strings entering any canonicalization path (values, keys, record fields) must be well-formed: no unpaired surrogates (U+D800 through U+DFFF appearing without their pair). This eliminates a class of cross-language divergence where JavaScript can hold lone surrogates in strings but Python cannot.

### Sort Order

Object keys are sorted by UTF-16 code-unit order. In JavaScript this is the default `.sort()`. In Python, use `sorted(keys, key=lambda k: k.encode("utf-16-be"))`. These diverge for characters above the Basic Multilingual Plane (U+FFFF), where JavaScript uses surrogate pairs (two 16-bit code units) while Python uses single code points.

### Relationship to JCS (RFC 8785)

JCS canonicalizes JSON values directly and is injective over JSON without additional type tags, because the JSON grammar's own `{}`/`[]` notation already distinguishes objects from arrays. The Round-3 type-confusion collision (where `{a:1}` and `[["a",1]]` produced identical digests) was an artifact of our tuple-array representation, not something JCS would have had. Our type tags (`["M",...]`/`["L",...]`) serve the same role that JSON's native brace/bracket distinction serves in JCS.

We chose our form over JCS for three reasons. First, JCS mandates full ECMAScript number serialization (IEEE 754 double to shortest decimal), which is difficult to reproduce byte-identically in Python, Go, and Rust. Our safe-integer-only rule eliminates the entire class of float-formatting divergence by rejecting the inputs rather than specifying the output. Second, our record canonicalization uses fixed field positions (positional determinism), enabling O(1) streaming append without re-sorting the record on every write. Third, our canonical form is computed before JSON serialization, so the hash input never depends on a particular JSON library's whitespace, key-ordering, or Unicode-escape behavior.

JCS gives you a ready-made injective standard for general JSON. We needed cross-language float safety, streaming-friendly positional layout, and serialization-layer independence, and accepted the cost of building injectivity ourselves.

## State File Invariants

The `.state.json` file contains:

- `lastHash` (string): hash of the most recently written record (chain head for resume)
- `rotationBoundaryHash` (string, required): expected `previousHash` of the first record in the current log file
- `checkpointSequence` (number): monotonically increasing checkpoint counter
- `totalRecordCount` (number): total non-checkpoint records written

A state file missing any of these fields is treated as corrupt. The system refuses to start with a corrupt state file unless `--force-new-chain` is passed, which emits a signed `chain_break` record documenting the discontinuity.

### Two Persistence Functions

- `persistState()`: called only by `rotate()`. Sets `rotationBoundaryHash = lastHash` because the next file's first record will chain from the current chain head.
- `persistChainState()`: called only by `emitChainBreak()`. Preserves the existing `rotationBoundaryHash` because a mid-file chain break does not change which hash the first record of this file chains from.

## chain_break Records

A `chain_break` record is signed evidence of a discontinuity. It converts "gap in evidence" (which could be innocent or malicious) into "signed evidence of a gap" (which can be audited, attributed, and policy-gated).

`forceNewChain()` emits a chain_break and resets `lastHash`, `checkpointSequence`, `totalRecordCount`, and `recordsSinceCheckpoint`. It does NOT reset `rotationBoundaryHash`.

## Verification Modes

**Strict mode**: full chain available from genesis. Verifies absolute record counts, segment-initial anchors, adjacent deltas, and sequence monotonicity.

**Relative mode**: only a suffix of the chain available (e.g., after rotation or partial delivery). Verifies adjacent deltas and sequence monotonicity within the suffix. Reports `absoluteCountVerified: false` to signal that the consumer received an honestly-downgraded result, not a silently-incomplete one.

## Dual-Path Verification Architecture

Chain verification and signature verification serve different purposes and use different hash inputs.

**Chain continuity (octets-first):** Each record's `previousHash` must equal `SHA-256(stored bytes of prior line)`. The verifier hashes the raw JSONL line as written to disk, with no parse/re-serialize round-trip. This eliminates cross-language serialization fragility: any implementation that can read bytes and compute SHA-256 can verify chain continuity, regardless of its JSON library's key-ordering or whitespace behavior.

`verifyChainLines(lines)` implements this path. `verifyAuditLog(path, signer, {verifyChain: true})` also uses raw-line hashing internally.

**Signature verification (canonical form):** The attestation signature covers the canonical form of the record (type-tagged, positionally-ordered, sans attestation field). Verifying a signature requires recomputing this canonical form from the parsed record. This is correct because the producer computed the signature the same way.

`verifyAuditLog(path, signer)` implements this path (strips attestation, canonicalizes, verifies).

**Why the separation matters:** A re-serialization-based chain verifier would appear to work in single-language deployments (where `JSON.stringify` is deterministic). It breaks silently when logs are produced by one language and verified by another, because `JSON.stringify(JSON.parse(line))` is not guaranteed to reproduce the original bytes. The octets-first approach avoids this entire class of fragility.

`verifyChain(records)` is retained as a convenience for callers who only have pre-parsed records. It uses `JSON.stringify` re-serialization and is correct only when key insertion-order is preserved (guaranteed in V8/Node.js for string keys). Callers with access to raw lines should prefer `verifyChainLines`.

## Pitfalls Found During Design Review

These are the non-obvious bugs discovered across six rounds of adversarial review. Each required a design change, not just a code fix.

**Type-confusion collision (Round 3).** Without type tags, `{a: 1}` canonicalized to `[["a", 1]]`, which is indistinguishable from the array `[["a", 1]]`. An attacker controlling extension values could craft an array that produces the same digest as a different object. Type tags (`["M", ...]` vs `["L", ...]`) make the mapping injective.

**UTF-16 vs code-point sort divergence (Round 4).** JavaScript's `.sort()` compares by UTF-16 code units. Python's `sorted()` compares by code points. For characters above U+FFFF, these produce different orderings. Same object, two canonical forms, two digests. The fix mandates UTF-16 code-unit order and provides a conformance vector proving the divergence.

**Lone surrogates (Round 4).** JavaScript strings can contain unpaired surrogates. Python strings generally cannot. `JSON.stringify` behavior on lone surrogates varies across engines. Rather than specifying divergent behaviors, the design rejects lone surrogates entirely.

**Dual-purpose state field (Round 5).** `lastHash` was serving two masters: "resume base for next record" and "expected linkage of first record in this file." After a `forceNewChain`, these diverge. The solution splits them into `lastHash` (runtime chain head) and `rotationBoundaryHash` (file-boundary claim).

**Null-skip bypass (Round 6).** When `rotationBoundaryHash` was null (no rotation yet), the linkage check was skipped. An attacker planting a state file without the field could bypass detection. The fix mandates `"genesis"` as the initial value, matching the first record's natural `previousHash`.

**Fail-open on corrupt first line (Round 5).** If the first line didn't parse, `firstRecordPrevHash` remained undefined and the linkage check silently skipped. Now: corrupt first line = refuse to start.

**Fixed-size head buffer (Round 4).** A 4KB head buffer silently truncated large first records, causing parse failure that mapped to the fail-open above. The grow-to-newline approach (with 1MB cap) handles any legitimate record size.

## Conformance Testing

Cross-language conformance is verified by two independent implementations:

- `test/vectors/verify-checkpoint.mjs` (JavaScript/Node.js)
- `test/vectors/verify-checkpoint.py` (Python)

Both consume the same `test/vectors/checkpoint.json` vector file (46 vectors). The vectors cover: checkpoint canonicalization, chain hashing, truncation detection, canonicalizeValue (including astral-plane keys and surrogate rejection), extensions digest, rotation boundary, sequence regression, chain break, and verification modes.

Adding a new implementation requires passing all 46 vectors. The astral-plane sort vector specifically catches implementations using code-point sort instead of UTF-16 code-unit sort.

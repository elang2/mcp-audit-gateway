# Security Design

This document describes the security invariants of the attestation and checkpoint subsystem, the threat model they address, and the pitfalls discovered during adversarial design review.

## Threat Model

The attestation layer defends against three classes of attack on audit logs:

1. **Truncation**: an operator or compromised process deletes records from the tail of a log file to hide evidence of tool calls.
2. **Tampering**: modification of individual records (field values, ordering, or removal) after they are written.
3. **Planted state**: an attacker with filesystem access fabricates or replays the `.state.json` file to make the system resume from a false position, enabling silent truncation of the real log.

The system does NOT defend against an attacker who holds the signing key AND has write access to both log and state files simultaneously. At that point, the attacker can forge new valid records. Key management (KMS, HSM, or envelope encryption) is the defense for that layer.

## Deployment Modes and Trust Boundaries

The proxy operates in two modes. Their security properties differ, and the difference matters when placing this system in a control matrix.

### Wrap mode (`mcp-audit wrap -- <cmd>`)

The wrap process spawns a single upstream MCP server as a child on stdio and forwards messages transparently in both directions. Only `tools/call` responses are signed and logged; every other JSON-RPC method passes through untouched.

Wrap mode performs **no pre-execution evaluation**. There is no policy engine, no principal, no rate limit, no allowlist. The wrap does not decide anything about the call before it is forwarded to the upstream. Its role is post-completion evidence only: sign what happened, chain it, expose it for later verification.

The signing key defaults to HMAC-SHA256 with a per-user secret auto-generated in `~/.mcp-audit/key.hex` on first run. The user is the sole verifier by construction.

### Full gateway mode (`mcp-audit serve <config>`)

The gateway multiplexes multiple upstream MCP servers, applies a policy artifact to each `tools/call`, and only forwards calls that the policy admits. The policy engine (`src/policy/engine.ts`) evaluates a call against an ordered rule list and produces a `PolicyDecision` before dispatch. What is evaluated:

- **principal** — from a configurable header, matched against `rule.principals`
- **tool identity** — `namespace` and `name` matched against `rule.tools` / `rule.namespaces`
- **rate limit** — per-principal, per-tool tumbling-window counters (1-minute and 1-hour windows, aligned to each key's first invocation and reset on the first hit after expiry)
- **default effect** — `allow` or `deny` when no rule matches

A `deny` decision short-circuits before the upstream call is made. An `allow` decision proceeds to dispatch. Both decisions produce a `DecisionContext` (`{principal, toolName, toolNamespace, toolUpstream, matchedRule, effect}`), which is hashed with `computeDecisionContextDigest` and emitted as the audit record's `decisionContextDigest` field. The digest binds the audit record to the policy inputs that produced the outcome; a verifier holding the policy artifact can re-derive whether the decision was admissible under that policy.

Gateway mode defaults to **Ed25519** signing (portable public verification) rather than HMAC.

### What the gateway policy layer is and is not

The gateway is a **partial pre-execution control**. It performs authorization gating before the upstream call is made, over the dimensions `{principal, tool, namespace, rate}`. It does not implement:

- payload-hash execution tickets that would prevent post-authorization payload substitution
- content inspection of the request body (no keyword filters, no injection detection)
- delegation-authority reasoning across nested agent identities
- witnessed epoch finality (see "External Anchoring", below)

The audit-chain layer is orthogonal: it commits post-completion evidence for whichever calls did reach the upstream, whether the gateway admitted them or wrap mode passed them through unconditionally.

## Attacker Capability Levels

The threat model above groups attacks by target (truncation, tampering, planted state). The table below restates them by attacker capability. Two terms used in the rows: `rotationBoundaryHash` is the expected `previousHash` of the first record in the current log file, persisted at rotation (defined in *State File Invariants*, below); `chain_break` is a signed record marking a discontinuity in the chain (defined in *chain_break Records*, below).

| Capability | What the attacker can do | Detection surface | Preventive surface |
|---|---|---|---|
| **Filesystem-only** (read/write log and state files; no key) | Truncate tail, reorder records, delete records, plant `.state.json` | Chain hash break, `rotationBoundaryHash` mismatch, checkpoint absolute-count mismatch, planted-state linkage check | None — this system is evidence, not prevention. Chain evidence is preserved even under filesystem write. |
| **Key compromise** (attacker holds signing key; no host control) | Forge new well-signed records that verify individually | Cannot forge past records if a `rotationBoundaryHash` or checkpoint tip was already retained externally by a verifier. Fresh forgeries verify individually but cannot re-anchor a previously witnessed chain tip. | None. Recovery requires key rotation and re-anchoring from a trusted checkpoint. |
| **Full host / process compromise** (attacker controls gateway process, key, log, state) | Produce arbitrary well-signed, chain-consistent records; suppress real records before they hit the log | An internally-consistent chain cannot be distinguished from a truthful one by inspecting the chain alone. Detection requires **external anchoring** (below). | Out of scope for the audit-chain layer. This is the boundary the threat model explicitly names as a non-goal. |
| **Direct tool bypass** (attacker reaches the upstream tool without traversing the proxy) | Execute tool calls that never touch the audit chain | The audit log shows nothing; **absence from the chain is not evidence that no execution occurred**. | Requires network-level or process-level mandatory mediation outside this system. Kubernetes NetworkPolicy, Linux namespace isolation, or an equivalent path-enforcement mechanism must ensure the tool has no reachable path other than through the proxy. |

The last two rows are the ones most easily overlooked. A system that verifies its own chain end-to-end proves internal consistency, not that the log is complete. The controls needed are outside the audit chain: external anchoring for full-host compromise, and network-level mandatory mediation for the direct-bypass surface.

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

**AuditRecord**: `[id, timestamp, method, toolName, namespace, upstream, principal, durationMs, success, errorCode, previousHash]` with four optional fields inserted at defined positions when present: `decisionContextDigest`, `extensionsDigest`, `aiInvocation`, `parties`. Three of these pass through as scalars or already-canonical arrays; `aiInvocation` is wrapped via `canonicalizeValue`, which applies the M/L type tags recursively.

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

### Why type-tagged canonical form

The type tags (`["M", ...]` for objects, `["L", ...]` for arrays) exist to close a class of digest collision. Without them, an object like `{a: 1}` and the array `[["a", 1]]` collapse to the same tuple representation and produce identical digests. This was the Round-3 type-confusion collision. Tagging makes the mapping injective at the canonicalization layer, before any serialization step is involved.

Three design constraints ruled out canonicalizing serialized JSON directly:

- **Cross-language float safety.** Byte-identical serialization of IEEE 754 doubles across JavaScript, Python, Go, and Rust is difficult in practice. This form sidesteps float-formatting divergence entirely by rejecting non-safe-integer numbers at the input, rather than specifying an output format.
- **Streaming-friendly layout.** Record canonicalization uses fixed field positions (positional determinism), so appending a record is O(1); no re-sort is needed on every write.
- **Serialization-layer independence.** The canonical form is computed before JSON serialization, so the hash input never depends on any JSON library's whitespace, key-ordering, or Unicode-escape behavior.

Injectivity is built into the type-tag rule; the three constraints above dictated its specific form.

A separate canonicalization discipline, RFC 8785 (JSON Canonicalization Scheme), is used elsewhere in this codebase for tool-definition canonicalization, where inputs are flat objects and cross-language float safety is not the primary concern. That layer is out of scope for this document, which addresses AuditRecord attestation.

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

**Why the separation matters:** A re-serialization-based chain verifier would appear to work in single-language deployments (where `JSON.stringify` is deterministic). It breaks silently when logs are produced by one language and verified by another, because `JSON.stringify(JSON.parse(line))` is not guaranteed to reproduce the original bytes. The octets-first approach avoids this failure mode.

`verifyChain(records)` is retained as a convenience for callers who only have pre-parsed records. It uses `JSON.stringify` re-serialization and is correct only when key insertion-order is preserved (guaranteed in V8/Node.js for string keys). Callers with access to raw lines should prefer `verifyChainLines`.

## Verifier Trust Models

The signer choice determines who can independently verify records and under what assumptions.

HMAC-SHA256 is symmetric. Anyone holding the secret can produce and verify signatures, so signer and verifier are the same principal. Sharing the secret with a third party would let them verify but also let them forge. That is fine for self-attestation and single-tenant deployments; it rules out external audit.

Ed25519 is asymmetric. The private key signs; the public key verifies. The public key can be published alongside the audit log, or distributed via `.well-known/agent-governance.json`, without weakening signature integrity. An external auditor can verify records without holding any secret, which is what makes the evidence portable.

Neither signer is an independent witness. If the same host controls the gateway, the signing key, and the audit log, that host can produce arbitrary well-signed records for events that never happened. Signer choice raises the bar (an attacker must obtain the key rather than only filesystem write access) but does not cross the operator-independence boundary. Crossing that boundary requires external anchoring.

## Pitfalls Found During Design Review

These are the non-obvious bugs discovered across six rounds of adversarial review. Each required a design change, not just a code fix.

**Type-confusion collision (Round 3).** Without type tags, `{a: 1}` canonicalized to `[["a", 1]]`, which is indistinguishable from the array `[["a", 1]]`. An attacker controlling extension values could craft an array that produces the same digest as a different object. Type tags (`["M", ...]` vs `["L", ...]`) make the mapping injective.

**UTF-16 vs code-point sort divergence (Round 4).** JavaScript's `.sort()` compares by UTF-16 code units. Python's `sorted()` compares by code points. For characters above U+FFFF, these produce different orderings. Same object, two canonical forms, two digests. The fix mandates UTF-16 code-unit order and provides a conformance vector proving the divergence.

**Lone surrogates (Round 4).** JavaScript strings can contain unpaired surrogates. Python strings generally cannot. `JSON.stringify` behavior on lone surrogates varies across engines. The design rejects them at the input rather than trying to specify a common downstream behavior.

**Dual-purpose state field (Round 5).** `lastHash` had two incompatible jobs: resume base for the next record, and expected linkage of the first record in this file. After a `forceNewChain`, these diverge. The fix splits them into `lastHash` (runtime chain head) and `rotationBoundaryHash` (file-boundary claim).

**Null-skip bypass (Round 6).** When `rotationBoundaryHash` was null (no rotation yet), the linkage check was skipped. An attacker planting a state file without the field could bypass detection. The fix mandates `"genesis"` as the initial value, matching the first record's natural `previousHash`.

**Fail-open on corrupt first line (Round 5).** If the first line didn't parse, `firstRecordPrevHash` remained undefined and the linkage check silently skipped. Now: corrupt first line = refuse to start.

**Fixed-size head buffer (Round 4).** A 4KB head buffer silently truncated large first records, causing parse failure that mapped to the fail-open above. The grow-to-newline approach (with 1MB cap) handles any legitimate record size.

## Conformance Testing

Cross-language conformance is verified by two independent implementations:

- `test/vectors/verify-checkpoint.mjs` (JavaScript/Node.js)
- `test/vectors/verify-checkpoint.py` (Python)

Both consume the same `test/vectors/checkpoint.json` vector file (46 vectors). The vectors cover: checkpoint canonicalization, chain hashing, truncation detection, canonicalizeValue (including astral-plane keys and surrogate rejection), extensions digest, rotation boundary, sequence regression, chain break, and verification modes.

Adding a new implementation requires passing all 46 vectors. The astral-plane sort vector specifically catches implementations using code-point sort instead of UTF-16 code-unit sort.

A parallel harness, **C-REC** (Canonical Record Equivalence Check, `npm run c-rec:verify`), diffs the canonicalization output against a pinned reference canonicalizer row-by-row. The reference is [`notboatanchor/gif`](https://github.com/notboatanchor/gif) — the SEP-3004 ([modelcontextprotocol/modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)) author's reference implementation — vendored VERBATIM under Apache-2.0 at `test/vectors/c-rec/vendored/gif/audit-record-contract.ts` and pinned to a specific commit. It appears as `GIF` in the harness output. Provenance, license, and the pin-bump procedure are documented in `test/vectors/c-rec/SOURCE.md` and `test/vectors/c-rec/PIN-HISTORY.md`. The gate passes only when the local canonicalizer matches this reference byte-for-byte on the KAT set. Vector 2 of the C-REC harness enforces the safe-integer producer contract referenced in *Producer-requirement contract*, below.

## Reproducible Verification

### Wrap mode

`mcp-audit wrap` is spawned by an MCP client as a child on stdio; it is not a standalone daemon. Register it in the client's config, run some tool calls through the client, then verify the log.

Example `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "@mcp-audit-gateway/core", "wrap", "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

Restart the client, exercise a few tool calls, then verify:

```bash
mcp-audit verify ~/.mcp-audit/audit.jsonl
# Total records: N   Valid: N   Invalid: 0

# Tamper: flip one field in one record.
sed -i.bak '1s/"success":true/"success":false/' ~/.mcp-audit/audit.jsonl
mcp-audit verify ~/.mcp-audit/audit.jsonl
# Invalid: 1 with reason "signature mismatch"

# Suffix deletion — chain does not detect this without an external anchor.
sed '$d' ~/.mcp-audit/audit.jsonl > truncated.jsonl
mcp-audit verify truncated.jsonl
# Reports Valid: N-1, Invalid: 0 — internal consistency preserved.
# The chain does not detect truncation without an externally retained
# checkpoint tip. External anchoring is what closes this gap.
```

For a self-contained smoke test that does not require an MCP client, `docker/echo-server.mjs` implements a minimal stdio MCP echo endpoint the wrap can drive.

### Gateway mode

```bash
mcp-audit serve gateway.config.example.json
# Ed25519 key auto-generated on first run; public key path logged.
# Every tools/call gets a decisionContextDigest bound to the policy inputs.
```

### Cross-language conformance

The 46-vector suite and its two independent verifiers are specified in the *Conformance Testing* section above. Both must pass byte-identical for a change to land. To run them:

```bash
node test/vectors/verify-checkpoint.mjs      # JavaScript verifier
python3 test/vectors/verify-checkpoint.py    # Python verifier
npm run c-rec:verify                         # Canonical Record Equivalence Check (cross-implementation)
```

## Witness Projection

Audit records carry multi-party attribution via the `parties[]` array. Each entry has a `party` (a string identifier such as `"gateway"` or `"policy-engine"`), a `role` (`witness` | `asserter`), and a `scope` listing which fields it attests to. A `witness` attests to what it directly observed; an `asserter` claims what it or another party did. The distinction lives in the record bytes and downstream consumers can inspect it.

But consumers can silently collapse the distinction when aggregating. A dashboard counting successful calls without projecting to a role scope creates the illusion that a host's self-attestation is as reliable as the gateway's independent observation. The invariant that preserves the distinction is documentable in prose but is not machine-checkable without a scope-preserving read primitive.

`projectByRole(record, role, party?)` is the read-side primitive consumers call to preserve scope boundaries under aggregation. It returns a `WitnessProjection` type distinct from `AuditRecord`, so a projection cannot be mistaken for a record by the type system. The projection's canonical digest is computed via `projectionDigest(p)`, which wraps `canonicalizeValue(p)` as `JSON.stringify([PROJECTION_DOMAIN_TAG, canonical])`. The outer array wrap guarantees domain separation from record digests. `hashRecord` operates on the on-disk JSONL object form of a record, which serializes as `{...}`; that form is distinct from the positional-array shape used for signature input covered in *Canonical Form Specification*. A projection instead wraps as `[PROJECTION_DOMAIN_TAG, ...]`, so the two digest inputs cannot collide. Cross-implementation re-implementers must replicate both the canonicalization and the outer wrap.

### Producer-requirement contract

`projectionDigest` propagates `canonicalizeValue`'s throw behavior to projections: non-integer numbers, unsafe integers, and lone surrogates in projected field values all raise `canonicalizeValue: unsafe number ...` or the surrogate-well-formedness error. This is the same producer requirement Vector 2 of the C-REC harness enforces on records. `AuditRecord.durationMs` is currently assigned via `Date.now() - startTime` in every production path (integer milliseconds by convention, not by type); a future change to a float source would surface here as an `unsafe number` throw.

## External Anchoring (Current Status and Options)

The system does not currently publish chain tips to a transparency log or independent witness. Without an external anchor, the evidence is **self-attested**. A party that trusts the operator to sign truthfully can verify it; a party that treats the operator as potentially adversarial cannot. Reaching **operator-independent** tamper-evidence requires an external witness.

Two approaches are compatible with the current record format.

Epoch-granular anchoring means periodically submitting a signed chain tip (or checkpoint record) to an external witness. The witness could be a transparency log, a signed timestamp service, or a co-signing peer with a distinct key. It returns a signed receipt, which bounds the tampering-window granularity to the anchoring interval. This is enough when per-call witness is not required.

Per-call inclusion is the stronger option. Compute a Merkle root over each epoch's records, submit the root to a transparency-style log, and store per-call inclusion proofs alongside the audit log. A verifier holding a leaf record can then prove inclusion under a witnessed root without seeing the entire log. This is required when per-call witness independence matters.

Both options preserve the current chain format. Neither is implemented in this repo today; both are appropriate follow-ups if a deployment requires operator-independent evidence.

## Tamper Evidence Is Not Preventive Enforcement

Cryptographic signing is often quoted as if it were prevention. It is not. The attestation chain records what happened; it does not decide whether it should happen. A record that is signed, chained, and witnessed under an external anchor still describes an action that already executed. If preventing the action was the requirement, the chain is not the control that satisfies it.

In control matrix terms, this system provides post-completion execution evidence in both modes, and pre-execution authorization gating in full gateway mode only (over the four dimensions above). Execution-time payload integrity (authorization-bound execution) is not implemented. Witnessed independence is not implemented either; external anchoring is the path there.

The audit chain and the policy engine should be scored as separate controls in a control matrix, not collapsed into a single "cryptographic commit" label.

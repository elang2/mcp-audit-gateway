# v0.3.x Backlog (Deferred, Non-Blocking)

Items explicitly deferred during Rounds 1-6 review. None block the v0.3.0 tag. All should become issues before fixture work begins.

## Executable verification-mode vectors

Add conformance vectors for `verifyCompleteness` covering: strict-mode pass, relative-mode pass with `absoluteCountVerified: false`, and delta-mismatch negative case. Currently tested only via unit tests, not cross-language vectors.

Deferred in: Round 3 (to the APS fixture pass).

## Relative-mode post-break segment anchoring

In relative mode, a suffix starting with `chain_break, rec1, rec2, ckpt(recordCount=2)` could verify that the first checkpoint's count matches records between the break and it. Currently skipped (relative mode can't verify absolute counts). The question is whether relative mode should verify counts *within its own suffix* while still reporting `absoluteCountVerified: false`.

Deferred in: Round 4, Q3.

## State file signing

Sign the state file with the same key used for records. Prevents fabrication by an attacker with file access but no key access. Does NOT prevent replay of an old validly-signed state file (the linkage check handles replay). Additive, non-breaking.

Deferred in: Round 4, Q2.

## Richer chainBreaks array

Replace `hasChainBreak: boolean` in verification results with `chainBreaks: Array<{index, reason, priorHead?, timestamp}>`. A consumer deciding whether to accept a broken chain needs which/why/when. Verifier-side, non-breaking.

Deferred in: Round 3, Q3.

## Python verifier for APS action-ref-v1 vectors

The 46 checkpoint conformance vectors have JS + Python parity. The 51 adapted APS action-ref-v1 vectors are JS-only (the upstream APS conformance suite is JS-only). Cross-language parity applies to our native vectors; adapted third-party fixtures match the upstream language. A Python runner would strengthen the parity story but is not blocking.

Added: Post-APS adaptation.

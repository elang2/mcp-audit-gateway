# C-REC side-by-side comparison

Companion vectors for SEP-3004
([modelcontextprotocol/modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)).
Shows byte-level divergence between two canonicalization approaches on
the same inputs.

- **GIF sorted-JSON**: from [notboatanchor/gif](https://github.com/notboatanchor/gif/tree/e1f02a95506e81e7766c3ba3a684ecad7cfff12f) @ `e1f02a95506e81e7766c3ba3a684ecad7cfff12f`, the SEP-3004 author's reference implementation. Used VERBATIM in this repo at `./vendored/gif/audit-record-contract.ts`, Apache-2.0 licensed. See `./SOURCE.md` for provenance and license terms.
- **mcp-audit-gateway type-tagged M/L**: the algorithm at `src/attestation/signer.ts`. Original work, MIT licensed per the repository root LICENSE.

## Files

- `harness.ts` — imports GIF's `canonicalize` from the vendored file and this repo's `canonicalizeValue` from `src/`. Defines the KAT anchor, the 11-row side-by-side fixture set, and the five producer-requirement vectors. Standalone runnable via tsx: prints the markdown side-by-side to stdout.
- `verify-kat.ts` — CI gate. Proves the vendored GIF's `canonicalize()` applied to the sealed KAT_INPUT reproduces `KAT_HASH_CG` (`d494769c1ae442ea...`) byte-for-byte, and locks in the accept/throw contract shapes each producer vector exercises. Exits non-zero on any drift.
- `vendored/gif/` — the vendored Apache-2.0 material (see `./SOURCE.md`).
- `reports/` — payload generator for a versioned markdown file the SEP-3004 comment links to.
- `PIN-HISTORY.md` — audit trail of GIF pin changes.

## Run

```bash
# CI gates
npm run c-rec:verify         # runs verify-kat.ts (KAT + producer-vector contracts)
npm run c-rec:report:check   # verifies committed payload matches fresh regen

# Generation
npm run c-rec:table          # prints the side-by-side to stdout via harness.ts
npm run c-rec:report         # regenerates reports/SEP-3004-comment-payload.md
```

## What the KAT anchor proves

If `verify-kat.ts` prints `OK  KAT reproduces  d494769c1ae442ea...`, then GIF's vendored `canonicalize()` matches the SEP-3004 sealed reference byte-for-byte. Any divergence the table shows is real algorithmic difference, not implementation drift.

## Why vendor GIF instead of reimplementing

The harness uses GIF verbatim rather than reimplementing. Vendoring satisfies Apache-2.0 §4 attribution: SPDX header, copyright, and NOTICE all preserved and reproduced without derivative-work reasoning. Every comparison the harness prints uses GIF's actual bytes on one side and this repo's actual bytes on the other.

## CI

Wired into `.github/workflows/ci.yml` under the `vectors:` job so every push runs `verify-kat.ts` and `c-rec:report:check`. A change to GIF's vendored source, to `src/attestation/signer.ts`, or to the payload generator that produces different bytes without a refresh of the committed payload will fail the workflow.

## Updating the pin

If GIF releases a new canonicalizer that changes the KAT hash, `verify-kat.ts` will fail. When that happens:

1. Audit the diff between the old pin (`e1f02a95506e81e7766c3ba3a684ecad7cfff12f`) and the new upstream commit. Is the change a documented semantic revision, or a subtle behavior shift? The former is safe to accept; the latter needs discussion on the SEP-3004 thread before the pin bumps.
2. Recompute the KAT hash from GIF's own test suite at the new commit. Do not compute it from a reimplementation.
3. Record the change: append a row to `PIN-HISTORY.md` with old pin, new pin, old KAT, new KAT, link to the SEP-3004 or GIF discussion that motivated the change, date, and reviewer.
4. Replace `./vendored/gif/audit-record-contract.ts` with the new upstream file verbatim. Preserve the SPDX/copyright header. Update `./vendored/gif/LICENSE` and `./vendored/gif/NOTICE` if either changed upstream.
5. Update `KAT_EXPECTED` in `harness.ts`.
6. Re-run `npm run c-rec:verify` locally.
7. The PR bumping the pin should link to the SEP-3004 or GIF discussion in its description.

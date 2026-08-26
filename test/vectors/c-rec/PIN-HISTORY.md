# GIF Pin History

Audit trail of changes to the pinned GIF commit vendored at
`./vendored/gif/audit-record-contract.ts`. Every pin bump must be
recorded here before landing.

## Format

| Date | Old pin | New pin | Old KAT | New KAT | Vendored file SHA-256 | Motivation | Reviewer |
|------|---------|---------|---------|---------|-----------------------|------------|----------|

## History

| Date | Old pin | New pin | Old KAT | New KAT | Vendored file SHA-256 | Motivation | Reviewer |
|------|---------|---------|---------|---------|-----------------------|------------|----------|
| 2026-08-26 | (seed) | `e1f02a95506e81e7766c3ba3a684ecad7cfff12f` | (seed) | `d494769c1ae442ea88dd190068747abf63c0568a3b856f85791b1a50a99d48b4` | `ed4e75adecd71a6e6ec504b1ffb1b7d762c737e80515476bc76672fddbd46a77` | Initial C-REC harness (v0.7.8). GIF pin chosen as the SEP-3004 reference implementation cited in the SEP PR description. Vendored VERBATIM (not reimplemented). | elang2 |

## Column semantics

- **Old pin / New pin**: full 40-char commit SHA of `notboatanchor/gif` at the previous and new pinned state.
- **Old KAT / New KAT**: `KAT_EXPECTED` value in `harness.ts` before and after the pin bump.
- **Vendored file SHA-256**: sha256 of `./vendored/gif/audit-record-contract.ts` at the new pin.
- **Motivation**: link to the SEP-3004 or GIF discussion, PR, or issue that prompted the pin bump.
- **Reviewer**: GitHub handle of the person who audited the diff.

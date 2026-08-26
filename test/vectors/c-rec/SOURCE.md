# C-REC Fixture Provenance

## Origin

The Canonical Record Equivalence Check (C-REC) harness in this directory
compares two canonicalization algorithms side-by-side:

1. **GIF sorted-JSON** — used VERBATIM (byte-for-byte, unmodified) from
   [notboatanchor/gif](https://github.com/notboatanchor/gif), pinned to
   commit `e1f02a95506e81e7766c3ba3a684ecad7cfff12f`. The source file is
   vendored at `./vendored/gif/audit-record-contract.ts` with the SPDX
   license identifier and copyright header preserved. Upstream is
   Apache-2.0 licensed.

2. **This repo's type-tagged M/L canonicalizer** — original work in
   `src/attestation/signer.ts`, MIT licensed per the repository root
   LICENSE.

## Provenance chain

1. **notboatanchor/gif** (origin) — Apache-2.0 licensed reference
   implementation for SEP-3004. Vendored file at commit
   `e1f02a95506e81e7766c3ba3a684ecad7cfff12f`:
   - `mcp-server/conformance/audit-record-contract/audit-record-contract.ts`
     is copied to `./vendored/gif/audit-record-contract.ts` unmodified.
     Contains the `canonicalize()` function, the `normalizeString()`
     helper, `MAX_FIELD_LEN`, and other exports the harness uses.

2. **This directory** (vendored consumer) — imports `canonicalize` from
   the vendored file via tsx. No modifications to the vendored file.
   No reimplementation. The comparison is against GIF's actual bytes.

## License

Materials derived from GIF (`./vendored/gif/audit-record-contract.ts`)
are used under the terms of the Apache License, Version 2.0. A copy of
the license is included at `./vendored/gif/LICENSE`.

Preserved from GIF's source header (per Apache-2.0 §4(c)):

    SPDX-License-Identifier: Apache-2.0
    Copyright 2026 Notboatanchor Labs LLC

Preserved from GIF's NOTICE file (per Apache-2.0 §4(d)):

    gif — Governed Intelligence Framework
    Copyright 2026 Notboatanchor Labs LLC

    This product includes software developed by Notboatanchor Labs LLC
    (https://notboatanchor.com).

The NOTICE file is also included verbatim at `./vendored/gif/NOTICE`.

Since GIF's file is vendored VERBATIM (byte-for-byte, no modifications),
Apache-2.0 §4(b) modifications-notice does not apply. If a future
revision of this directory introduces modifications to
`./vendored/gif/audit-record-contract.ts`, those modifications must be
noted here and per-file (see Apache-2.0 §4).

The KAT_INPUT and KAT_EXPECTED constants in `./harness.ts` are the
sealed test-record and its published hash from the SEP-3004 discussion.
They are used here as reference data for CI verification.

The remainder of the C-REC harness in this directory (the harness
scaffolding, verify-kat.ts, the report generator in `reports/`, CI
wiring, and this documentation) is original work, MIT licensed per the
repository root LICENSE.

## Verification

The pinned SHA-256 of `./vendored/gif/audit-record-contract.ts` at
commit `e1f02a9` is:

    ed4e75adecd71a6e6ec504b1ffb1b7d762c737e80515476bc76672fddbd46a77

Reproducible via:

    curl -sL https://raw.githubusercontent.com/notboatanchor/gif/e1f02a95506e81e7766c3ba3a684ecad7cfff12f/mcp-server/conformance/audit-record-contract/audit-record-contract.ts | shasum -a 256

If this SHA changes upstream, `verify-kat.ts` will still pass if
GIF's KAT-relevant behavior is unchanged, but the pin should be
audited (see `./README.md` "Updating the pin").

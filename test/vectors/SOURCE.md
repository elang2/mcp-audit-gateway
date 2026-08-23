# APS Fixture Provenance

## Origin

The `aps-action-ref-v1-vectors.json` file contains conformance vectors
adapted from the APS (Agent Permission Scope) action-ref-v1 specification.

## Provenance chain

1. **giskard09/argentum-core** (origin) — authored the action-ref spec and
   generated the fixture data under Apache-2.0.
   Stable spec ref: `docs/spec/action-ref.md` at tag `action-ref-v1.0`.

2. **Agent-Authority-Conformance/aps-conformance-suite** (host) — mirrors
   the fixtures for cross-stack conformance testing under Apache-2.0.
   Path: `fixtures/cross-stack/action-ref-v1-negatives/`

3. **This repository** (adaptation) — subsets and consolidates the vectors
   into a single JSON file for our conformance runner.

## License

The adapted fixture data in `aps-action-ref-v1-vectors.json` is licensed
under the Apache License, Version 2.0. You may obtain a copy of the License
at <https://www.apache.org/licenses/LICENSE-2.0>.

The remainder of this directory (verifiers, canonicalization vectors,
checkpoint vectors) is MIT-licensed per the repository root LICENSE.

## Changes from upstream

- Selected 5 positive and 9 negative recomputation vectors (subset of the
  full suite; delegation/envelope semantics excluded as out-of-scope).
- Merged positive and negative fixtures into a single JSON file with
  top-level schema metadata.
- Added fixture integrity checks (each negative vector's drifted digest is
  independently verified as real before testing the reject path).
- Wrote `aps-action-ref-v1.mjs` — a new runner that exercises the
  fail-closed recomputation property using our SHA-256 + JCS primitives.

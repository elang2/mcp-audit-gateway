# Vector-set schema

Two JSON files carry the adversarial vector data. Both share the same top-level shape but differ in vector category focus.

## `adversarial-vectors.json`

Top-level object:

- **`format_version`** (string): semver of the schema. Current: `"1.0"`.
- **`description`** (string): one-paragraph human description of the file's scope.
- **`rationale`** (string): prose explaining the category coverage and why each category is present.
- **`vectors`** (array): vector objects (26 as of this cut).

Vector object:

- **`name`** (string): short kebab-case identifier, unique within the file.
- **`category`** (string): one of the categories in the coverage matrix (see below).
- **`expected_behavior`** (string): one of:
    - `"CONVERGE"`: all SDKs must produce byte-identical canonical output.
    - `"MAY_DIVERGE"`: divergence is observed and documented in the matrix; not a bug on its own.
    - `"REJECT"`: SDKs are expected to refuse the input (e.g. lone-surrogate strings that violate RFC 7493 / RFC 8785).
- **`record`** (object): the input record, in the tuple-array shape used by `canonicalization.json` in the parent directory. 11 required fields: `id`, `timestamp`, `method`, `toolName`, `namespace`, `upstream`, `principal`, `durationMs`, `success`, `errorCode`, `previousHash`.
- **`suspected_divergent_sdks`** (array of string): language ids (subset of `{ts, python, go, swift, java, kotlin, csharp, php, ruby, rust}`) expected to diverge on this vector based on prior fault modes.

## `nested-vectors.json`

Focus is on nesting-depth and container-shape divergence rather than character-level adversarial input. 5 vectors as of this cut. Shape is a subset of `adversarial-vectors.json`:

Top-level object:

- **`format_version`** (string): `"1.0"`.
- **`description`** (string): one-paragraph description.
- **`vectors`** (array): vector objects. No top-level `rationale` field.

Vector object (leaner than `adversarial-vectors.json`):

- **`name`** (string): unique kebab-case identifier.
- **`record`** (object): 11 fields matching the parent-directory tuple-array shape, with one substitution vs the adversarial file: `errorCode` is dropped and `aiInvocation` (object) is added. Optional nested keys `parties`, `extensionsDigest`, `decisionContextDigest` may appear on some vectors.

No `category`, `expected_behavior`, or `suspected_divergent_sdks` fields on the nested-vector object.

## Category coverage

`adversarial-vectors.json` targets ten Wycheproof-style categories:

- **`unicode-normalization`**: NFC vs NFD forms of the same visible string (café, hangul).
- **`lone-surrogate`**: unpaired UTF-16 surrogates in `\uXXXX` escapes: lone-high, lone-low, reversed-pair.
- **`deep-nesting`**: record shapes that push recursion.
- **`integer-edge`**: `2^53`, `2^53 + 1`, and negative counterparts to catch double-precision cutoffs from bignum SDKs.
- **`empty-structure`**: empty strings, empty objects, empty arrays in required fields.
- **`mixed-type-array`**: arrays of heterogeneous types.
- **`sort-collision`**: key-ordering divergences between UTF-16 code-unit sort and Unicode code-point sort (supplementary plane vs. PUA, emoji vs. PUA).
- **`zwj-rtl`**: zero-width joiners and right-to-left overrides.
- **`escaped-control`**: control chars that must be `\u`-escaped.
- **`boolean-integer-overlap`**: the Swift `NSNumber`-vs-`Bool` conflation and equivalents.

## Runner output schema

Each SDK-pair runner emits one JSON row per (signer, verifier, vector) tuple. Shape:

- **`signer`** (string): SDK id.
- **`verifier`** (string): SDK id.
- **`vector`** (string): the `name` field from the input vector.
- **`verified`** (boolean).
- **`signature_hex`** (string): hex-encoded 64-byte Ed25519 signature from the signer.
- **`canonical_bytes_hex`** (string): hex-encoded UTF-8 bytes of the signer's canonical form (for byte-comparison across SDKs on the same vector).

## Version compatibility

`format_version` follows semver. Consumers that read the file should:

- **Major version bump**: breaking change; a runner pinned to `1.x` will refuse to parse.
- **Minor version bump**: additive change (new optional fields on vector objects, new category values); a runner pinned to `1.0` should skip unknown fields.
- **Patch**: corrections to `description` / `rationale` prose only; no field or shape change.

The vector list itself grows monotonically within a major version. Vectors are never removed or renamed within a major; they may be added.

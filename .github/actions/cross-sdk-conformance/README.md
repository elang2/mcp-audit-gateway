# MCP Cross-SDK Conformance — GitHub Action

**One-line adoption.** Add this Action to any Model Context Protocol SDK repository to check whether that SDK's canonical JSON output byte-matches the reference test vectors from `elang2/mcp-audit-gateway`. Fail CI on divergences so wire-level regressions cannot land silently.

## Why should my SDK adopt this?

If your MCP SDK's canonical JSON output diverges from another SDK's output for the same input, records signed on your SDK cannot be byte-verified by the other SDK. Signature verification will fail without any tampering, and audit-trail chains signed on one SDK will break under any verifier written in a different language.

The reference vectors here surface every known cross-SDK divergence in one test suite. Running this on every PR catches new divergences before they ship.

## Minimum-viable adoption

Add this to your SDK repo's `.github/workflows/cross-sdk-conformance.yml`:

```yaml
name: MCP Cross-SDK Conformance

on: [pull_request, push]

jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: elang2/mcp-audit-gateway/.github/actions/cross-sdk-conformance@v0.7.8
        with:
          sdk: typescript  # or: python, go, swift, java, kotlin, csharp, php, ruby, rust
```

That's the entire adoption. The Action pins `elang2/mcp-audit-gateway` at tag `v0.7.8`, checks out the vectors, runs your SDK against 40 canonicalization tests plus the full 26-divergence matrix, and fails CI on any divergence.

## Inputs

| Input | Default | Description |
|---|---|---|
| `sdk` | required | Name of the SDK under test. One of `typescript`, `python`, `go`, `swift`, `java`, `kotlin`, `csharp`, `php`, `ruby`, `rust`. |
| `fail-on-divergence` | `fail` | Set to `warn` to emit warnings only. `fail` blocks the CI run on any divergence. |
| `layer` | `all` | `sdk` runs SDK-wire tests, `stdlib` runs JSON stdlib tests, `all` runs both. |
| `vectors-ref` | `v0.7.8` | Git ref of `elang2/mcp-audit-gateway` to pull vectors from. Pin to a tag for reproducible CI. |

## Outputs

| Output | Description |
|---|---|
| `divergence-count` | Number of test cases where the SDK diverged from the reference |
| `agreement-rate` | Fraction of test cases that matched the reference (0.0 to 1.0) |
| `results-json` | Path to the results JSON file with per-test byte comparisons |

## What the vectors cover

The reference test suite has 40 test cases across five categories:

- **Float representation** (6 tests): `1e20`, `1e-7`, `0.1+0.2`, minimum positive, maximum, subnormal
- **Numeric semantics** (3 tests): negative zero, 2^53+1 precision, negative integers
- **String encoding** (9 tests): control chars, forward slash, angle brackets, ampersand, Unicode NFC/NFD/astral, BMP escape, surrogate pairs
- **Key ordering** (7 tests): reverse insertion, numeric-string keys, nested depth, empty objects, absent keys, JSON-RPC id ordering
- **Null handling** (1 test): explicit null vs. absent field

## Verified divergences (current state)

The reference vectors are calibrated against ten official MCP SDKs. As of v0.7.8:

| SDK | Divergences | Agreement rate |
|---|---|---|
| TypeScript | 6 | 34/40 |
| Python | 3 | 37/40 |
| Go | 4 | 36/40 |
| Swift | 15 | 25/40 |
| Java | 8 | 32/40 |
| Kotlin | 5 | 35/40 |
| C# | 12 | 28/40 |
| PHP | 14 | 26/40 |
| Ruby | 3 | 37/40 |
| Rust | 3 | 37/40 |

(Numbers approximate; refresh via `./test/vectors/cross-sdk-diff.sh --json` for exact current state.)

## Attribution

If your SDK adopts this Action, please cite:

> Srinivasan, E. (2026). "Tamper-Evident Audit Trails for AI Agent Tool Invocations: Design Pitfalls, Cross-Language Conformance, and a Reference Implementation." Zenodo. https://doi.org/10.5281/zenodo.22070036

## License

MIT (matches `elang2/mcp-audit-gateway`).

## Support

Open an issue at [elang2/mcp-audit-gateway](https://github.com/elang2/mcp-audit-gateway/issues) with the `conformance-action` label.

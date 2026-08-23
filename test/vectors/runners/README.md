# Cross-SDK Differential Test Runners

Each runner serializes 40 test inputs using its language's standard JSON library and outputs results as JSON lines.

## Interface contract

Every runner must:
1. Output one JSON line per test: `{"test":"<name>","result":"<serialized>"}`
2. Use the language's standard/default JSON serializer (no custom formatting)
3. Output compact JSON (no whitespace between tokens)
4. Print to stdout, nothing to stderr on success
5. Exit 0 on success

## Running

```sh
# Run all detected languages:
../cross-sdk-diff.sh

# JSON output for CI:
../cross-sdk-diff.sh --json

# Generate markdown matrix:
../generate-matrix.sh > RESULTS.md

# Docker (all runtimes included):
docker build -t mcp-diff -f ../Dockerfile .. && docker run mcp-diff
```

## Adding a language

1. Create `serialize.<ext>` (or `Serialize.<ext>` for Java/Kotlin)
2. Implement all 40 tests (see serialize.js as reference)
3. Ensure it runs with `<runtime> serialize.<ext>` (no build step if possible)
4. The orchestrator auto-detects new runners by file extension

## Test names (all 40)

Floats: `float_1e20`, `float_1e-7`, `float_0.1+0.2`, `float_min_positive`, `float_max`, `float_subnormal`

Integers: `negative_zero`, `int_2pow53_plus1`, `int_max_safe`, `int_negative_large`

String escaping: `control_char_u0001`, `control_char_u001f`, `slash`, `backslash`, `angle_brackets`, `ampersand`, `tab_newline`, `null_byte`

Unicode: `unicode_nfc`, `unicode_nfd`, `unicode_astral`, `unicode_bmp_escape`, `unicode_surrogate_pair`

Object structure: `key_order_ba`, `key_numeric_strings`, `nested_depth`, `empty_nested`

MCP protocol: `null_value`, `empty_object`, `absent_key`, `isError_false`, `isError_absent`, `id_integer`, `id_string`

Boolean/null: `bool_false_vs_null`, `empty_string_key`, `array_with_nulls`

Complex structures: `tool_with_schema`, `content_array_mixed`, `error_response`

## Current runners

| File | Language | Runtime | Tests | Status |
|------|----------|---------|-------|--------|
| serialize.js | JavaScript | node | 40 | Tested |
| serialize.py | Python | python3 | 40 | Tested |
| serialize.rb | Ruby | ruby | 40 | Tested |
| serialize.go | Go | go run | 40 | Tested |
| serialize.swift | Swift | swift | 40 | Tested |
| Serialize.java | Java | javac+java | 40 | Tested |
| serialize.pl | Perl | perl | 40 | Tested |
| serialize.php | PHP | php | 40 | Needs testing |
| serialize.rs | Rust | rustc | 40 | Needs testing |
| serialize.kts | Kotlin | kotlinc | 40 | Needs testing |
| serialize.cs | C# | dotnet-script | 40 | Needs testing |

## Requirements per language

- **JavaScript**: node >= 18
- **Python**: python3 (stdlib only)
- **Ruby**: ruby (stdlib only)
- **Go**: go >= 1.21
- **Swift**: swift >= 5.9 (macOS/Linux)
- **Java**: JDK >= 11
- **Perl**: perl with JSON::PP (core since 5.14)
- **PHP**: php with json extension
- **Rust**: rustc (no external crates)
- **Kotlin**: kotlinc with org.json
- **C#**: dotnet-script or dotnet with System.Text.Json

## Latest results (7 languages, 40 tests)

- 12 tests agree across all languages
- 28 tests show divergent serialization
- Major divergence areas: float notation, negative zero, unicode escaping, key ordering

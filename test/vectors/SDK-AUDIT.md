# MCP SDK Serialization Audit

Complete audit of JSON serialization libraries and configurations across all 9 official MCP SDKs.

## SDK Serialization Libraries

| SDK | Library | Configuration | Source File |
|-----|---------|--------------|-------------|
| TypeScript | `JSON.stringify` | None (language default) | N/A (stdlib) |
| Python | pydantic v2 `model_dump_json()` | Rust-based serde engine; raw UTF-8; no `+` in exponents | `pydantic-core` (compiled) |
| Go | `encoding/json` | `SetEscapeHTML(false)` | `internal/jsonrpc2/messages.go` |
| Swift | Foundation `JSONEncoder` | **Server:** `.sortedKeys, .withoutEscapingSlashes`; **Client:** bare defaults | `Sources/MCP/Server/Server.swift`, `Sources/MCP/Client/Client.swift` |
| Kotlin | `kotlinx.serialization.json` | `explicitNulls=false`, `encodeDefaults=true`, `isLenient=true`, `classDiscriminatorMode=NONE` | `kotlin-sdk-core/.../types/jsonUtils.kt` |
| C# | `System.Text.Json` | `JsonSerializerDefaults.Web` (camelCase), `DefaultIgnoreCondition=WhenWritingNull`, `AllowReadingFromString` | `src/ModelContextProtocol.Core/McpJsonUtilities.cs` |
| Java | Jackson 2 | Default `new ObjectMapper()` — no custom features enabled | `mcp-json-jackson2/.../JacksonMcpJsonMapperSupplier.java` |
| Ruby | stdlib `JSON.generate` | No custom options | `lib/mcp/server/transports/stdio_transport.rb` |
| Rust | `serde_json` | Default `to_writer` — no custom config | `crates/rmcp/src/transport/async_rw.rs` |
| PHP | `json_encode()` | StdioTransport: `JSON_THROW_ON_ERROR` only; StatelessResponder adds `JSON_UNESCAPED_SLASHES` | `src/Server/Transport/StdioTransport.php`, `src/Server/Transport/Http/StatelessResponder.php` |

## Verified SDK-Level Divergences (4 SDKs, 40 tests)

Tested locally: TypeScript (reference), Python (pydantic v2), Go (SetEscapeHTML=false), Swift Server (JSONEncoder+sortedKeys).

**Result: 16 divergences, 24 agreements.**

### Float Representation (5 divergences)

| Test | TypeScript | Python SDK | Go SDK | Swift SDK |
|------|-----------|-----------|--------|-----------|
| `float_1e20` | `100000000000000000000` | `1e20` | `100000000000000000000` | `1e+20` |
| `float_1e-7` | `1e-7` | `1e-7` | `1e-7` | `9.9999999999999995e-08` |
| `float_0.1+0.2` | `0.30000000000000004` | `0.30000000000000004` | `0.3` | `0.30000000000000004` |
| `float_min_positive` | `5e-324` | `5e-324` | `5e-324` | `4.9406564584124654e-324` |
| `float_max` | `1.7976931348623157e+308` | `1.7976931348623157e308` | `1.7976931348623157e+308` | `1.7976931348623157e+308` |

**Impact:** Content digests, caching, and deduplication break when comparing serialized output across SDKs.

### Negative Zero and Integer Precision (2 divergences)

| Test | TypeScript | Python SDK | Go SDK | Swift SDK |
|------|-----------|-----------|--------|-----------|
| `negative_zero` | `0` | `-0.0` | `-0` | `-0` |
| `int_2pow53_plus1` | `9007199254740992` | `9007199254740993` | `9007199254740993` | `9007199254740993` |

**Impact:** TypeScript silently loses precision at 2^53+1. A tool argument `9007199254740993` round-trips through a TS SDK as `9007199254740992`.

### Key Ordering (9 divergences)

| Test | TypeScript | Python SDK | Go SDK | Swift SDK |
|------|-----------|-----------|--------|-----------|
| `key_order_ba` | insertion | insertion | **lexicographic** | **sorted** |
| `key_numeric_strings` | **V8 numeric** | insertion | **lexicographic** | **numeric-aware** |
| `null_value` | insertion | insertion | insertion | **sorted** |
| `empty_object` | insertion | insertion | insertion | **sorted** |
| `id_integer` | insertion | insertion | insertion | **sorted** |
| `id_string` | insertion | insertion | insertion | **sorted** |
| `tool_with_schema` | insertion | insertion | **nested sorted** | **all sorted** |
| `content_array_mixed` | insertion | insertion | **nested sorted** | **all sorted** |
| `error_response` | insertion | insertion | **nested sorted** | **all sorted** |

**Key ordering algorithms differ between Go and Swift:**
- Go (`encoding/json`): lexicographic byte comparison. Result: `"1" < "10" < "2"`.
- Swift (`JSONSerialization`): numeric-aware comparison (localizedStandardCompare). Result: `"1" < "2" < "10"`.
- TypeScript (V8): integer-indexed properties reordered numerically. Result: `"1" < "2" < "10"`.
- Python: insertion order preserved (dict since 3.7).

**Impact:** Key ordering affects content digests, signature verification, and any byte-level comparison. Go and Swift both sort but produce DIFFERENT orderings for numeric string keys.

### Unicode Handling (0 divergences)

All 4 SDKs preserve NFD/NFC form verbatim. Earlier report of Go normalizing NFD to NFC was caused by a stale compiled binary (verified by hex comparison: Go outputs NFD bytes unchanged).

## Critical Findings

### 1. Swift Client/Server Asymmetry

The Swift MCP SDK uses different JSONEncoder configurations for client and server:

| Component | `outputFormatting` | Key Order | Slash Handling |
|-----------|-------------------|-----------|----------------|
| Server | `.sortedKeys, .withoutEscapingSlashes` | Sorted | Unescaped |
| Client | (none) | Struct field order | Escaped (`\/`) |

A Swift MCP server and Swift MCP client exchanging the same data produce different wire bytes.

### 2. PHP Transport Asymmetry

The PHP MCP SDK uses different json_encode flags depending on transport:

| Transport | Flags | Slash Handling |
|-----------|-------|----------------|
| StdioTransport | `JSON_THROW_ON_ERROR` | Escaped (`\/`) |
| StatelessResponder (HTTP) | `JSON_THROW_ON_ERROR \| JSON_UNESCAPED_SLASHES` | Unescaped |

### 3. Go Sort Algorithm Mismatch with Swift

Both Go and Swift sort keys, but use different algorithms:
- `{"2":"b","1":"a","10":"c"}` in Go becomes `{"1":"a","10":"c","2":"b"}` (lex)
- Same input in Swift becomes `{"1":"a","2":"b","10":"c"}` (numeric-aware)

Two SDKs that both "sort keys" produce different wire output.

## Findings That Do NOT Survive at SDK Level

| Stdlib Finding | Status at SDK Level | Reason |
|---------------|--------------------|---------| 
| Go HTML escaping (`<>&`) | **False** | Go SDK calls `SetEscapeHTML(false)` |
| Python unicode escaping (non-ASCII) | **False** | pydantic v2 passes raw UTF-8 |
| Python float `1e+20` | **Changed** | pydantic emits `1e20` (no `+`), still diverges from TS |
| Swift slash escaping (`/`) | **False (server)** | Server uses `.withoutEscapingSlashes` |
| Float 1e-7 Python vs TS | **False** | pydantic `1e-7` matches TS `1e-7` |
| Go NFD normalization | **False** | Was stale binary artifact; Go preserves NFD |

## Runners Not Yet Verified

| Runner | Reason | Expected Behavior |
|--------|--------|-------------------|
| `serialize-sdk-java.java` | Needs Jackson JARs on classpath | Default ObjectMapper: no key sorting, standard float format |
| `serialize-sdk-kotlin.main.kts` | Needs kotlinc + kotlinx.serialization | `explicitNulls=false` omits null fields from @Serializable output |
| `serialize-sdk-csharp.cs` | Needs dotnet runtime | `WhenWritingNull` omits null-valued properties |
| `serialize-sdk-php.php` | Needs PHP 8.1+ | StdioTransport behavior (no UNESCAPED_SLASHES) |

## Methodology

Each SDK-level runner replicates the exact serialization configuration found in the SDK's source code. We read:
1. The dependency declaration (Cargo.toml, build.gradle.kts, .csproj, Package.swift, etc.)
2. The serializer configuration (ObjectMapper features, JsonSerializerOptions, Json{} builder, etc.)
3. The transport-layer call site where messages are actually written to the wire

The runner then uses that same library with the same configuration, bypassing the full SDK dependency graph but matching the serialization behavior exactly.

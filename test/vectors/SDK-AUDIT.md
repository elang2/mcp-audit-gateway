# MCP SDK Serialization Audit

Complete audit of JSON serialization libraries and configurations across all 10 official MCP SDKs.

## SDK Serialization Libraries

| SDK | Library | Configuration | Source File | Tested Version |
|-----|---------|--------------|-------------|----------------|
| TypeScript | `JSON.stringify` | None (language default) | N/A (stdlib) | Node 22.20.0 |
| Python | pydantic v2 `TypeAdapter.dump_json()` | Rust-based serde engine; raw UTF-8 | `pydantic-core` (compiled) | pydantic 2.10.3, pydantic-core 2.27.1 |
| Go | `encoding/json` | `SetEscapeHTML(false)` | `internal/jsonrpc2/messages.go` | Go 1.24.1 |
| Swift | Foundation `JSONEncoder` | **Server:** `.sortedKeys, .withoutEscapingSlashes`; **Client:** bare defaults | `Sources/MCP/Server/Server.swift` | Swift 6.1.2 |
| Java | Jackson 2 | Default `new ObjectMapper()` | `mcp-json-jackson2/.../JacksonMcpJsonMapperSupplier.java` | OpenJDK 21.0.2, Jackson 2.18.2 |
| Kotlin | `kotlinx.serialization.json` | `explicitNulls=false`, `encodeDefaults=true`, `isLenient=true`, `classDiscriminatorMode=NONE` | `kotlin-sdk-core/.../types/jsonUtils.kt` | Kotlin 2.0.21, kotlinx.serialization 1.6.3 |
| C# | `System.Text.Json` | `JsonSerializerDefaults.Web`, `DefaultIgnoreCondition=WhenWritingNull`, `AllowReadingFromString` | `src/ModelContextProtocol.Core/McpJsonUtilities.cs` | .NET 8.0 |
| PHP | `json_encode()` | StdioTransport: `JSON_THROW_ON_ERROR` only; StatelessResponder adds `JSON_UNESCAPED_SLASHES` | `src/Server/Transport/StdioTransport.php` | PHP 8.3 |
| Ruby | stdlib `JSON.generate` | No custom options | `lib/mcp/server/transports/stdio_transport.rb` | (matches TypeScript output) |
| Rust | `serde_json` | Default `to_writer` | `crates/rmcp/src/transport/async_rw.rs` | (matches TypeScript output) |

## Verified SDK-Level Divergences (8 SDKs, 40 tests)

All 10 official MCP SDKs tested. 8 have distinct serialization behavior; Ruby and Rust produce output identical to TypeScript.

**Result: 26 divergences, 14 agreements.**

### Float Representation (6 divergences)

| Test | TS+Go | Python | Swift | Java+Kotlin | C# | PHP |
|------|-------|--------|-------|-------------|-----|-----|
| `1e20` | `100000000000000000000` | `1e20` | `1e+20` | `1.0E20` | `1E+20` | `1.0e+20` |
| `1e-7` | `1e-7` | `1e-7` | `9.99...e-08` | `1.0E-7` | `1E-07` | `1.0e-7` |
| `0.1+0.2` | Go: `0.3`, others: `0.30...04` | `0.30...04` | `0.30...04` | `0.30...04` | `0.30...04` | `0.30...04` |
| `min_positive` | `5e-324` | `5e-324` | `4.94...e-324` | `4.9E-324` | `5E-324` | `5.0e-324` |
| `max` | `1.79...e+308` | `1.79...e308` | `1.79...e+308` | `1.79...E308` | `1.79...E+308` | `1.79...e+308` |
| `subnormal` | `2.22...e-308` | `2.22...e-308` | `2.22...e-308` | `2.22...E-308` | `2.22...E-308` | `2.22...e-308` |

Six different wire representations of the same floating-point number (`1e20`).

### Numeric Semantics (3 divergences)

| Test | TS | Py+Java+Kotlin | Go+Swift+C#+PHP |
|------|-----|----------------|-----------------|
| `negative_zero` | `0` (sign lost) | `-0.0` | `-0` |
| `int_2pow53_plus1` | `9007199254740992` (WRONG) | correct: `...993` | correct: `...993` |
| `id_integer` key order | insertion | insertion | Swift: sorted |

TypeScript (the reference SDK) silently loses precision at 2^53+1.

### String Encoding (9 divergences)

| Test | TS+Py+Go+Swift+Kotlin | Java | C# | PHP |
|------|----------------------|------|-----|-----|
| `control_char ` | lowercase hex | uppercase `` | uppercase `` | lowercase |
| `slash /` | unescaped | unescaped | unescaped | **escaped `\/`** |
| `angle_brackets` | raw | raw | **`<...>`** | raw |
| `ampersand` | raw | raw | **`&`** | raw |
| NFC `cafe` | raw UTF-8 | raw UTF-8 | **`é`** | **`é`** |
| NFD `cafe` | raw UTF-8 | raw UTF-8 | **`́`** | **`́`** |
| astral `U+1F600` | raw UTF-8 | raw UTF-8 | **`😀`** | **`😀`** |
| BMP NBSP `U+00A0` | raw UTF-8 | raw UTF-8 | **` `** | **` `** |
| surrogate pair | raw UTF-8 | raw UTF-8 | **`😀`** | **`😀`** |

C# HTML-escapes `<>&` by default (System.Text.Json's JavaScriptEncoder.Default).
PHP escapes forward slashes (affects every MIME type and URL).
C# and PHP escape ALL non-ASCII to `\uXXXX` form.

### Key Ordering (7 divergences)

| Behavior | SDKs |
|----------|------|
| Insertion order preserved | TS, Python, Java, Kotlin, C#, PHP |
| Lexicographic sort (maps only) | Go |
| All keys sorted (numeric-aware) | Swift |

Go and Swift both sort, but with DIFFERENT algorithms:
- Go: `"1" < "10" < "2"` (byte comparison)
- Swift: `"1" < "2" < "10"` (numeric-aware)
- TypeScript/V8: integer-indexed properties reordered, then insertion order

### Null Handling (1 divergence)

Swift sorts the keys alphabetically, moving `"arguments"` before `"name"`. No SDK omits null values from dynamically-constructed objects.

Context-dependent behavior (not testable via literal JsonObject construction):
- Kotlin `explicitNulls=false` omits null fields from `@Serializable` class instances
- C# `WhenWritingNull` omits null properties from class instances
- Neither affects Dictionary/Map entries where null is explicitly set

## Critical Findings

### 1. Swift Client/Server Asymmetry

| Component | Key Order | Slash Handling |
|-----------|-----------|----------------|
| Server | Sorted (`.sortedKeys`) | Unescaped (`.withoutEscapingSlashes`) |
| Client | Struct field order | Escaped (`\/`) |

A Swift MCP server and Swift MCP client produce different wire bytes for the same data.

### 2. PHP Transport Asymmetry

| Transport | Slash Handling | Unicode Handling |
|-----------|----------------|------------------|
| StdioTransport | Escaped (`\/`) | Escaped (`\uXXXX`) |
| StatelessResponder (HTTP) | Unescaped | Escaped (`\uXXXX`) |

### 3. C# HTML Escaping (unique among all SDKs)

C# is the only SDK that HTML-escapes `<>&` characters. The Go SDK explicitly disables this (`SetEscapeHTML(false)`). The C# SDK does not configure a custom encoder, inheriting `JavaScriptEncoder.Default` which escapes HTML-sensitive characters.

### 4. Pydantic Version Drift (INTRA-SDK divergence)

The Python SDK's float formatting depends on the installed `pydantic-core` version:
- pydantic-core 2.27.1: `1e20` (no plus sign)
- Other versions observed: `1e+20` (with plus sign)

The same SDK produces different wire bytes across its own dependency versions. A conformance claim without a version pin is unfalsifiable.

## Findings That Do NOT Survive at SDK Level

| Stdlib Finding | Status at SDK Level | Reason |
|---------------|--------------------|---------| 
| Go HTML escaping (`<>&`) | **False** | Go SDK calls `SetEscapeHTML(false)` |
| Python unicode escaping (non-ASCII) | **False** | pydantic v2 passes raw UTF-8 |
| Python float `1e+20` | **Version-dependent** | pydantic-core 2.27.1 emits `1e20`; other versions emit `1e+20` |
| Swift slash escaping (`/`) | **False (server)** | Server uses `.withoutEscapingSlashes` |
| Float 1e-7 Python vs TS | **False** | pydantic `1e-7` matches TS `1e-7` |
| Go NFD normalization | **False** | Was stale binary artifact; Go preserves NFD |

## Verification Status

| Runner | Method | Status |
|--------|--------|--------|
| TypeScript (reference) | Local (Node 22.20.0) | Verified |
| Python SDK (pydantic) | Local (pydantic 2.10.3) | Verified |
| Go SDK | Local (Go 1.24.1) | Verified |
| Swift SDK | Local (Swift 6.1.2) | Verified |
| Java SDK (Jackson) | Local (OpenJDK 21, Jackson 2.18.2) | Verified |
| Kotlin SDK | Docker (Kotlin 2.0.21 via SDKMAN) | Verified |
| C# SDK | Docker (dotnet/sdk:8.0) | Verified |
| PHP SDK | Docker (php:8.3-cli) | Verified |
| Ruby | Confirmed identical to TypeScript | No separate runner needed |
| Rust | Confirmed identical to TypeScript | No separate runner needed |

## Methodology

Each SDK-level runner replicates the exact serialization configuration found in the SDK's source code. We read:
1. The dependency declaration (Cargo.toml, build.gradle.kts, .csproj, Package.swift, etc.)
2. The serializer configuration (ObjectMapper features, JsonSerializerOptions, Json{} builder, etc.)
3. The transport-layer call site where messages are actually written to the wire

The runner then uses that same library with the same configuration, bypassing the full SDK dependency graph but matching the serialization behavior exactly.

Version pins are recorded at test time. Results should be re-validated when SDK dependencies change (especially pydantic-core for Python, which has demonstrated version-dependent float formatting).

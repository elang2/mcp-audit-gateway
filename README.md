# mcp-audit

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22070815.svg)](https://doi.org/10.5281/zenodo.22070815)

Your AI agent made 847 tool calls yesterday. Can you verify what it did?

Tamper-evident audit trail for AI agent tool calls.

## Setup (10 seconds)

Before:
```json
{
  "command": "npx",
  "args": ["@modelcontextprotocol/server-github"]
}
```

After:
```json
{
  "command": "npx",
  "args": ["mcp-audit", "wrap", "--", "npx", "@modelcontextprotocol/server-github"]
}
```

Every tool call is now cryptographically signed and hash-chained. Nothing else changes. The MCP server works exactly as before.

## What it does

```
$ mcp-audit tail

✓ 14:32:01 github/create_pr                 234ms  bf7a2f62
✓ 14:32:03 github/list_issues                89ms  a1c4e890
✗ 14:32:05 fs/delete_file                    12ms  c3d9f012
✓ 14:32:08 github/merge_pr                  456ms  e5f6a7b8
```

Every entry is signed with HMAC-SHA256 and chained to the previous record. Tamper with any entry and verification fails. Delete an entry and the chain breaks.

## Verify integrity

```bash
$ mcp-audit verify ~/.mcp-audit/audit.jsonl

Results:
  Total records: 847
  Valid: 847
  Invalid: 0

All records verified successfully.
```

## How it works

```
┌────────────┐       ┌───────────┐       ┌────────────┐
│ MCP Client │──────▶│ mcp-audit │──────▶│ MCP Server │
│ (Claude,   │◀──────│   wrap    │◀──────│ (any)      │
│  Cursor)   │       └─────┬─────┘       └────────────┘
└────────────┘             │
                           ▼
                    ~/.mcp-audit/
                    audit.jsonl
```

The wrap command spawns your MCP server as a child process and sits between the client and server on stdio. It forwards ALL messages transparently. Only `tools/call` responses get signed and logged. Everything else passes through untouched.

On first run, a signing key is auto-generated in `~/.mcp-audit/key.hex`. No configuration needed.

## Audit record format

```json
{
  "id": "bf7a2f62-4d0f-4cce-afd2-cbfbf7bca2a5",
  "timestamp": "2026-08-16T14:32:01.000Z",
  "method": "tools/call",
  "toolName": "github/create_pr",
  "args": {"title": "Fix bug", "body": "..."},
  "durationMs": 234,
  "success": true,
  "previousHash": "8a3f2b...",
  "attestation": "7c4d9e..."
}
```

The `attestation` is an HMAC-SHA256 signature over the record's canonical fields. The `previousHash` is SHA-256 of the preceding record. Together they detect tampering, ordering, and completeness.

## Use with Claude Desktop

`claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["mcp-audit", "wrap", "--", "npx", "@modelcontextprotocol/server-github"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["mcp-audit", "wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

## Use with Claude Code

`.claude/hooks/mcp-servers.json` or directly in your MCP server command — prefix with `mcp-audit wrap --`.

## CLI

```bash
mcp-audit wrap -- <cmd> [args]    # Wrap any MCP server
mcp-audit tail                    # Live stream of tool calls
mcp-audit verify <log>            # Verify chain integrity
mcp-audit serve [config]          # Full gateway (policy + OTel)
mcp-audit keygen [dir]            # Generate Ed25519 key pair
```

## Full gateway mode

For teams that also need access control, rate limiting, and multi-server routing:

```bash
mcp-audit serve gateway.config.json
```

The full gateway adds:
- Policy engine (glob-based ACLs, per-principal rate limits)
- Tool namespacing across multiple upstream MCP servers
- OpenTelemetry traces and metrics export
- Upstream health management with automatic reconnection
- Ed25519 signatures (stronger than HMAC, portable verification)

See [gateway configuration](gateway.config.example.json) for the full schema.

## Install

```bash
npm install -g @mcp-audit-gateway/core
```

This installs the `mcp-audit` CLI globally. Or use without installing:
```bash
npx @mcp-audit-gateway/core wrap -- <your mcp server command>
```

## Attestation layer

The signing and verification subsystem goes beyond per-record HMAC. It provides tamper-evidence across log rotation, crash recovery, and multi-file chains.

Checkpoint records let a consumer detect tail truncation by stashing a single hash externally. The chain carries forward across file rotations (no silent resets). Forced restarts emit signed `chain_break` records instead of quietly starting fresh.

The canonical form is type-tagged and injective, avoids JCS's float-formatting problem by rejecting unsafe numbers entirely, and has proven cross-language parity via 46 conformance vectors (JS + Python). See [SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) for the full specification and threat model.

## Cross-SDK differential testing (10 SDKs, 26 divergences)

MCP has 10 official SDKs and no cross-SDK conformance testing. We built a [Wycheproof](https://github.com/google/wycheproof)-style differential harness that runs 40 serialization edge-case tests across all 10 SDKs and reports where they disagree.

**Result: 26 wire-level divergences across 8 distinct serializers.**

### Headline findings

| Category | What we found |
|----------|--------------|
| Float formatting | 6 SDKs produce 6 different wire representations of `1e20` |
| Key ordering | 3 incompatible algorithms (insertion, lexicographic, numeric-aware) |
| Integer precision | TypeScript silently loses precision at 2^53+1 |
| String encoding | C# HTML-escapes `<>&`, PHP escapes `/`, Python escapes all non-ASCII |
| Null handling | Kotlin drops null fields entirely, Swift preserves them |

### Float divergence example (`1e20`)

```
TypeScript:  100000000000000000000
Python:      1e20
Swift:       1e+20
Java:        1.0E20
C#:          1E+20
PHP:         1.0e+20
```

Six SDKs, six different bytes on the wire. If your hash-chain implementation assumes consistent serialization across SDKs, it breaks silently.

### SDKs tested

| SDK | Serializer | Version tested |
|-----|-----------|----------------|
| TypeScript | `JSON.stringify` (V8) | Node 22.20.0 |
| Python | pydantic-core (Rust serde) | pydantic 2.10.3 |
| Go | `encoding/json` | Go 1.24.1 |
| Swift | Foundation `JSONEncoder` | Swift 6.1.2 |
| Java | Jackson 2 | OpenJDK 21, Jackson 2.18.2 |
| Kotlin | `kotlinx.serialization` | Kotlin 2.0.21 |
| C# | `System.Text.Json` | .NET 8.0 |
| PHP | `json_encode()` | PHP 8.3 |
| Ruby | stdlib `JSON.generate` | Ruby 3.3 |
| Rust | `serde_json` | rmcp 3.1.4, Rust 1.88 |

### Run it yourself

```bash
# Clone and run the full matrix
git clone https://github.com/elang2/mcp-audit-gateway.git
cd mcp-audit-gateway && npm ci

./test/vectors/cross-sdk-diff.sh              # full matrix (stdlib + SDK layers)
./test/vectors/cross-sdk-diff.sh --layer sdk  # SDK wire-level only
./test/vectors/cross-sdk-diff.sh --json       # machine-readable output
```

Output shows per-test agreement/divergence across all SDKs with exact byte representations.

### Use in your CI

Drop this into `.github/workflows/cross-sdk-conformance.yml` to catch serialization regressions in your own MCP server or client:

```yaml
name: Cross-SDK Conformance
on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: '3.3'

      - uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '21'

      - name: Install mcp-audit-gateway
        run: npm install @mcp-audit-gateway/core

      - name: Run cross-SDK differential tests
        run: |
          npx cross-sdk-diff --json > results.json
          npx cross-sdk-diff

      - name: Fail on new divergences
        run: |
          DIVS=$(python3 -c "
          import json
          with open('results.json') as f:
              d = json.load(f)
          print(sum(1 for x in d if not x['agree']))
          ")
          echo "Divergences found: $DIVS"
          if [ "$DIVS" -gt 26 ]; then
            echo "ERROR: New divergences detected (was 26, now $DIVS)"
            exit 1
          fi
```

Or run just the conformance vectors (no language SDKs required, only Node.js):

```yaml
name: Canonicalization Conformance
on: [push, pull_request]

jobs:
  vectors:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
      - run: node test/vectors/verify-checkpoint.mjs
      - run: node test/vectors/aps-action-ref-v1.mjs
```

### Methodology

The harness uses a Wycheproof-inspired approach: define edge-case inputs (floats at precision boundaries, non-ASCII strings, nested key orders), serialize them through each SDK's actual JSON encoder, and compare the raw bytes. No mocking. Each SDK runner imports the real serialization library that the official MCP SDK uses in production.

Full divergence table with per-test byte comparisons: [SDK-AUDIT.md](test/vectors/SDK-AUDIT.md)

The audit gateway's canonicalization was designed to be immune to all 26 divergence classes: safe integers only (eliminates float formatting), explicit field order (eliminates sort disagreements), surrogate rejection (eliminates encoding divergences). See [SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) for the threat model.

## Examples

### Verify your canonicalization against ours

```javascript
import { canonicalize } from '@mcp-audit-gateway/core';

const record = {
  method: 'tools/call',
  toolName: 'github/create_pr',
  args: { title: 'Fix bug', body: '...' },
  timestamp: '2026-08-16T14:32:01.000Z'
};

const canonical = canonicalize(record);
// Deterministic bytes regardless of key insertion order,
// float formatting, or platform JSON encoder
```

### Python verification (cross-language parity)

```python
from mcp_audit_gateway import verify_chain

results = verify_chain("/path/to/audit.jsonl")
assert results.valid == results.total
assert results.chain_breaks == 0
```

### Run the conformance vectors against your own implementation

```bash
# 46 cross-language vectors (JS + Python must agree on every hash)
node test/vectors/verify-checkpoint.mjs
python3 test/vectors/verify-checkpoint.py

# 51 APS action-ref-v1 vectors
node test/vectors/aps-action-ref-v1.mjs

# Full 10-SDK matrix
./test/vectors/cross-sdk-diff.sh
```

### Docker (self-contained, no host dependencies)

```bash
docker build -f test/vectors/Dockerfile -t cross-sdk-diff .
docker run --rm cross-sdk-diff
```

## Conformance

This implementation satisfies the following properties (verified by cross-language conformance vectors and unit tests):

- Injective canonical form (no cross-type digest collisions)
- Cross-language sort equivalence (UTF-16 code-unit order)
- Unpaired surrogate rejection
- Hash chain continuity across log rotation
- Planted state detection on startup
- No false-positive after legitimate chain break
- Fail-closed on corrupt or oversized input
- Segmented monotonicity at chain_break boundaries
- Consumer-anchored completeness via checkpoint records
- Memory-bounded init (1MB cap)

APS action-ref-v1 conformance: 51/51 vectors passing (JCS recomputation + fail-closed digest comparison).

## Testing

```bash
npm test                                    # unit tests
node test/vectors/verify-checkpoint.mjs     # JS conformance vectors
python3 test/vectors/verify-checkpoint.py   # Python conformance vectors
node test/vectors/aps-action-ref-v1.mjs     # 51 APS vectors
./test/vectors/cross-sdk-diff.sh            # 10-SDK differential test
```

## License

MIT

The APS conformance fixtures (`test/vectors/aps-action-ref-v1-vectors.json`)
are adapted from upstream Apache-2.0 sources. See
[test/vectors/SOURCE.md](test/vectors/SOURCE.md) for provenance and terms.

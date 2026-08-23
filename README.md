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
npm test                                    # 149 unit tests
node test/vectors/verify-checkpoint.mjs     # 46 JS conformance vectors
python3 test/vectors/verify-checkpoint.py   # 46 Python conformance vectors
node test/vectors/aps-action-ref-v1.mjs     # 51 APS vectors
```

## License

MIT

The APS conformance fixtures (`test/vectors/aps-action-ref-v1-vectors.json`)
are adapted from upstream Apache-2.0 sources. See
[test/vectors/SOURCE.md](test/vectors/SOURCE.md) for provenance and terms.

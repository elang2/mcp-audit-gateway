# Examples

## claude-desktop.json

Minimal config for wrapping Claude Desktop's MCP servers with audit logging. Uses HMAC-SHA256 (no key file needed, just a secret). Denies write operations by default.

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "audited": {
      "command": "node",
      "args": ["/path/to/mcp-audit-gateway/dist/cli.js", "serve", "/path/to/examples/claude-desktop.json"],
      "env": {
        "GITHUB_TOKEN": "ghp_...",
        "AUDIT_SECRET": "your-64-char-hex-secret"
      }
    }
  }
}
```

## multi-agent-production.json

Production deployment with multiple upstream services, strict deny-by-default policy, per-principal rate limits, Ed25519 signing, and OTel export. Shows the typical setup for a team running multiple AI agents against shared infrastructure.

Key patterns demonstrated:
- Default deny with explicit allow rules per agent identity
- Rate limiting on destructive operations (deploy)
- Separate namespaces isolating database, deploy, and monitoring tools
- OTel export to a collector for centralized observability
- Large rotation threshold for high-volume environments

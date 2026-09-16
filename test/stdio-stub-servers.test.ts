import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// The two stub servers shipped for container demos and for Glama's introspection
// pass are hand-rolled rather than SDK-based, so nothing else in the suite would
// notice if their wire framing drifted from MCP stdio. It did: both used LSP-style
// Content-Length headers, which made them silently unreachable to every real
// client — the connect below hung instead of failing loudly.
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const STUBS = [
  { file: "glama-demo-server.mjs", name: "mcp-audit-gateway", tool: "audit_status", args: {} },
  { file: "docker/echo-server.mjs", name: "echo-server", tool: "echo", args: { message: "hi" } },
];

describe.each(STUBS)("$file speaks MCP stdio", ({ file, name, tool, args }) => {
  it("completes the handshake, lists tools, and answers a call", async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve(REPO_ROOT, file)],
      cwd: REPO_ROOT,
    });
    const client = new Client({ name: "framing-regression", version: "1.0.0" });

    await client.connect(transport);
    try {
      expect(client.getServerVersion()?.name).toBe(name);

      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name)).toContain(tool);

      const result = await client.callTool({ name: tool, arguments: args });
      expect(result.content).toBeDefined();
    } finally {
      await client.close();
    }
  }, 20_000);
});

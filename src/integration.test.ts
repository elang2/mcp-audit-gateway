import { describe, it, expect, afterEach } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Gateway } from "./proxy/gateway.js";
import { HmacSigner } from "./attestation/signer.js";
import { verifyAuditLog } from "./attestation/verify.js";
import { unlink } from "node:fs/promises";
import type { GatewayConfig } from "./types.js";

const AUDIT_PATH = "/tmp/integration-test-audit.jsonl";

const config: GatewayConfig = {
  name: "test-integration",
  version: "0.1.0",
  listen: { transport: "streamable-http", port: 3199, host: "127.0.0.1" },
  upstreams: [],
  policy: {
    defaultEffect: "allow",
    rules: [
      { effect: "deny", principals: ["agent:blocked"], tools: ["*/secret_*"] },
    ],
  },
  attestation: { enabled: true, algorithm: "hmac-sha256", secret: "c".repeat(64), includeParams: false, includeResult: false },
  telemetry: { enabled: false, serviceName: "test", sampleRate: 0 },
  auditLog: { enabled: true, path: AUDIT_PATH, rotateAfterMb: 10 },
};

describe("Integration: Gateway with in-memory MCP server", () => {
  afterEach(async () => {
    try { await unlink(AUDIT_PATH); } catch {}
  });

  it("routes a tool call through the gateway and produces a verifiable audit record", async () => {
    const server = new Server(
      { name: "echo-server", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(
      ListToolsRequestSchema,
      async () => ({
        tools: [
          { name: "echo", description: "Echoes input", inputSchema: { type: "object" as const, properties: { msg: { type: "string" } } } },
          { name: "secret_tool", description: "Secret", inputSchema: { type: "object" as const } },
        ],
      }),
    );

    server.setRequestHandler(
      CallToolRequestSchema,
      async (request) => ({
        content: [{ type: "text", text: `echo: ${request.params.arguments?.msg}` }],
      }),
    );

    const gateway = new Gateway(config);
    await gateway.init();

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test-client", version: "1.0.0" }, { capabilities: {} });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const toolsResult = await client.listTools();
    gateway.registerUpstreamTools("echo-server", "echo", toolsResult.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })));

    const listed = await gateway.handleToolsList();
    expect(listed.tools).toHaveLength(2);
    const names = listed.tools.map((t: any) => t.name);
    expect(names).toContain("echo/echo");
    expect(names).toContain("echo/secret_tool");

    const filteredList = await gateway.handleToolsList("agent:blocked");
    const filteredNames = filteredList.tools.map((t: any) => t.name);
    expect(filteredNames).toContain("echo/echo");
    expect(filteredNames).not.toContain("echo/secret_tool");

    // Make a denied call to generate an audit record
    try {
      await gateway.handleToolsCall("echo/secret_tool", {}, "agent:blocked");
    } catch {
      // expected denial
    }

    // Make a call to unknown tool to generate another audit record
    try {
      await gateway.handleToolsCall("echo/nonexistent", {});
    } catch {
      // expected
    }

    const signer = new HmacSigner("c".repeat(64));
    const verifyResult = await verifyAuditLog(AUDIT_PATH, signer);
    expect(verifyResult.total).toBe(2);
    expect(verifyResult.valid).toBe(2);
    expect(verifyResult.invalid).toBe(0);

    await client.close();
    await server.close();
  });
});

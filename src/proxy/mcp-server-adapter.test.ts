import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ListToolsResultSchema,
  CompatibilityCallToolResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Gateway } from "./gateway.js";
import { McpServerAdapter } from "./mcp-server-adapter.js";
import type { GatewayConfig } from "../types.js";
import { unlink } from "node:fs/promises";

const AUDIT_PATH = "/tmp/mcp-adapter-test-audit.jsonl";

const testConfig: GatewayConfig = {
  name: "adapter-test-gateway",
  version: "0.2.0",
  listen: { transport: "streamable-http", port: 3200, host: "127.0.0.1" },
  upstreams: [
    {
      name: "mock-server",
      namespace: "mock",
      transport: { type: "stdio", command: "echo", args: [] },
    },
  ],
  policy: {
    defaultEffect: "allow",
    rules: [
      {
        effect: "deny",
        principals: ["agent:restricted"],
        tools: ["mock/secret_tool"],
      },
    ],
  },
  attestation: {
    enabled: true,
    algorithm: "hmac-sha256",
    secret: "b".repeat(64),
    includeParams: false,
    includeResult: false,
  },
  telemetry: { enabled: false, serviceName: "test", sampleRate: 0 },
  auditLog: { enabled: true, path: AUDIT_PATH, rotateAfterMb: 10 },
};

describe("McpServerAdapter", () => {
  let gateway: Gateway;
  let adapter: McpServerAdapter;
  let client: Client;

  beforeEach(async () => {
    gateway = new Gateway(testConfig);
    await gateway.init();

    // Register tools manually (simulating upstream discovery)
    gateway.registerUpstreamTools("mock-server", "mock", [
      {
        name: "greet",
        description: "Greets a user",
        inputSchema: { type: "object", properties: { name: { type: "string" } } },
      },
      {
        name: "secret_tool",
        description: "A restricted tool",
        inputSchema: { type: "object" },
      },
    ]);

    adapter = new McpServerAdapter(gateway, {
      name: "adapter-test-gateway",
      version: "0.2.0",
      resolvePrincipal: (meta) => meta?.requestIdentity as string | undefined,
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} },
    );

    await adapter.connect(serverTransport);
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
    await adapter.close();
    try {
      await unlink(AUDIT_PATH);
    } catch {
      // file may not exist
    }
  });

  describe("tools/list", () => {
    it("lists tools with namespace prefixes via the SDK client", async () => {
      const result = await client.listTools();

      expect(result.tools.length).toBe(2);
      const names = result.tools.map((t) => t.name);
      expect(names).toContain("mock/greet");
      expect(names).toContain("mock/secret_tool");
    });

    it("includes tool descriptions through the adapter", async () => {
      const result = await client.listTools();

      const greet = result.tools.find((t) => t.name === "mock/greet");
      expect(greet).toBeDefined();
      expect(greet!.description).toBe("Greets a user");
    });

    it("applies policy filtering when requestIdentity is provided", async () => {
      // Use a custom request with _meta to pass identity
      const result = await client.request(
        {
          method: "tools/list",
          params: {
            _meta: { requestIdentity: "agent:restricted" },
          },
        },
        ListToolsResultSchema,
      );

      const tools = result.tools;
      const names = tools.map((t) => t.name);
      expect(names).toContain("mock/greet");
      expect(names).not.toContain("mock/secret_tool");
    });
  });

  describe("tools/call", () => {
    it("returns attestation metadata in tool call responses", async () => {
      // Call a tool that will be denied by policy, which produces attestation
      const result = await client.request(
        {
          method: "tools/call",
          params: {
            name: "mock/secret_tool",
            arguments: {},
            _meta: { requestIdentity: "agent:restricted" },
          },
        },
        CompatibilityCallToolResultSchema,
      );

      // Should get an error response with attestation metadata
      const meta = (result as any)._meta;
      expect(meta).toBeDefined();
      expect(meta["x-gateway-attestation/v1"]).toBeDefined();
      expect(meta["x-gateway-attestation/v1"].auditId).toBeDefined();
      expect(meta["x-gateway-attestation/v1"].attestation).toBeDefined();
      expect(meta["x-gateway-attestation/v1"].timestamp).toBeDefined();

      // Should be flagged as an error
      expect((result as any).isError).toBe(true);
    });

    it("returns error content for unknown tools with attestation", async () => {
      const result = await client.request(
        {
          method: "tools/call",
          params: {
            name: "mock/nonexistent",
            arguments: {},
          },
        },
        CompatibilityCallToolResultSchema,
      );

      expect((result as any).isError).toBe(true);
      const content = (result as any).content;
      expect(content).toHaveLength(1);
      expect(content[0].type).toBe("text");
      expect(content[0].text).toContain("Unknown tool");

      // Attestation metadata should still be present
      const meta = (result as any)._meta;
      expect(meta["x-gateway-attestation/v1"].auditId).toBeDefined();
    });
  });

  describe("server capabilities", () => {
    it("advertises tools capability", () => {
      const caps = client.getServerCapabilities();
      expect(caps?.tools).toBeDefined();
    });

    it("advertises gateway extension in experimental capabilities", () => {
      const caps = client.getServerCapabilities();
      expect(caps?.experimental).toBeDefined();
      expect((caps?.experimental as any)["x-gateway-routing/v1"]).toBeDefined();
      expect((caps?.experimental as any)["x-gateway-attestation/v1"]).toBeDefined();
    });
  });
});

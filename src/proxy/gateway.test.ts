import { describe, it, expect, beforeEach } from "vitest";
import { Gateway } from "./gateway.js";
import type { GatewayConfig } from "../types.js";

const testConfig: GatewayConfig = {
  name: "test-gateway",
  version: "0.1.0",
  listen: { transport: "streamable-http", port: 3100, host: "127.0.0.1" },
  upstreams: [
    {
      name: "test-server",
      namespace: "test",
      transport: { type: "stdio", command: "echo", args: [] },
    },
  ],
  policy: {
    defaultEffect: "allow",
    rules: [
      {
        effect: "deny",
        principals: ["agent:blocked"],
        tools: ["test/dangerous_tool"],
      },
    ],
  },
  attestation: { enabled: true, algorithm: "hmac-sha256", secret: "a".repeat(64), includeParams: false, includeResult: false },
  telemetry: { enabled: false, serviceName: "test", sampleRate: 0 },
  auditLog: { enabled: true, path: "/tmp/test-audit.jsonl", rotateAfterMb: 10 },
  checkpoint: { enabled: false, intervalRecords: 100, intervalSeconds: 60, trigger: "whichever_first" as const },
};

describe("Gateway", () => {
  let gateway: Gateway;

  beforeEach(async () => {
    gateway = new Gateway(testConfig);
    await gateway.init();

    gateway.registerUpstreamTools("test-server", "test", [
      { name: "safe_tool", description: "A safe tool" },
      { name: "dangerous_tool", description: "A dangerous tool" },
      { name: "read_data", description: "Read some data" },
    ]);
  });

  describe("server/discover", () => {
    it("advertises gateway capabilities", () => {
      const discover = gateway.getServerDiscover();
      expect(discover.capabilities).toHaveProperty("gateway");
      const gw = (discover.capabilities as any).gateway;
      expect(gw.namespacing).toBe(true);
      expect(gw.filtering).toBe(true);
      expect(gw.routing).toBe(true);
      expect(gw.attestation).toBe(true);
      expect(gw.upstreamCount).toBe(1);
    });
  });

  describe("tools/list", () => {
    it("returns namespaced tools", async () => {
      const result = await gateway.handleToolsList();
      expect(result.tools).toHaveLength(3);
      const names = result.tools.map((t: any) => t.name);
      expect(names).toContain("test/safe_tool");
      expect(names).toContain("test/dangerous_tool");
      expect(names).toContain("test/read_data");
    });

    it("filters tools based on policy", async () => {
      const result = await gateway.handleToolsList("agent:blocked");
      const names = result.tools.map((t: any) => t.name);
      expect(names).toContain("test/safe_tool");
      expect(names).not.toContain("test/dangerous_tool");
      expect(names).toContain("test/read_data");
    });

    it("includes filtering metadata", async () => {
      const result = await gateway.handleToolsList("agent:blocked");
      const meta = result._meta as any;
      expect(meta["x-gateway-routing/v1"].filteringApplied).toBe(true);
      expect(meta["x-gateway-routing/v1"].totalToolsPreFilter).toBe(3);
      expect(meta["x-gateway-routing/v1"].totalToolsPostFilter).toBe(2);
    });
  });

  describe("tools/call", () => {
    it("rejects unknown tools", async () => {
      await expect(
        gateway.handleToolsCall("nonexistent/tool", {}),
      ).rejects.toThrow("Unknown tool");
    });

    it("rejects unauthorized tool calls", async () => {
      await expect(
        gateway.handleToolsCall("test/dangerous_tool", {}, "agent:blocked"),
      ).rejects.toThrow();
    });

    it("includes aiInvocation context and client-asserter party", async () => {
      const aiInvocation = { turnId: "turn-abc", invocationReason: "user asked", model: "claude-4" };
      try {
        await gateway.handleToolsCall("test/safe_tool", {}, "user:test", undefined, aiInvocation);
      } catch {
        // upstream not connected, but the record should still be created on error path
      }
      // The denied path gives us a record we can inspect
      try {
        await gateway.handleToolsCall("test/dangerous_tool", {}, "agent:blocked", undefined, aiInvocation);
      } catch (err: unknown) {
        const record = (err as { auditRecord: { aiInvocation?: unknown; parties?: Array<{ party: string; role: string; scope: string[] }> } }).auditRecord;
        expect(record.aiInvocation).toEqual(aiInvocation);
        expect(record.parties).toContainEqual({ party: "client", role: "asserter", scope: ["aiInvocation"] });
      }
    });
  });

  describe("status", () => {
    it("reports gateway and upstream health", () => {
      const status = gateway.getStatus();
      expect(status.gateway.status).toBe("healthy");
      expect(status.upstreams).toHaveLength(1);
      expect(status.upstreams[0].name).toBe("test-server");
      expect(status.aggregate.totalTools).toBe(3);
    });
  });
});

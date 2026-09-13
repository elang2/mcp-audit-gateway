import { describe, it, expect, beforeEach } from "vitest";
import { Gateway, ToolCallError } from "./gateway.js";
import { computeDecisionContextDigest } from "../policy/engine.js";
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
  toolIntegrity: { enabled: false, action: "record" as const },
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

    it("party provenance boundary: no client-asserted field in gateway witness scope", async () => {
      const aiInvocation = { turnId: "turn-xyz", invocationReason: "test", model: "gpt-4o" };
      try {
        await gateway.handleToolsCall("test/dangerous_tool", {}, "agent:blocked", undefined, aiInvocation);
      } catch (err: unknown) {
        const record = (err as { auditRecord: { parties?: Array<{ party: string; role: string; scope: string[] }> } }).auditRecord;
        const gatewayParty = record.parties?.find(p => p.party === "gateway" && p.role === "witness");
        const clientParty = record.parties?.find(p => p.party === "client" && p.role === "asserter");
        expect(gatewayParty).toBeDefined();
        expect(clientParty).toBeDefined();
        expect(gatewayParty!.scope).not.toContain("aiInvocation");
        expect(clientParty!.scope).not.toContain("id");
        expect(clientParty!.scope).not.toContain("timestamp");
        expect(clientParty!.scope).not.toContain("toolName");
        expect(clientParty!.scope).not.toContain("success");
        const overlap = gatewayParty!.scope.filter(f => clientParty!.scope.includes(f));
        expect(overlap).toHaveLength(0);
      }
    });

    it("party provenance boundary: reduction across boundary produces weaker claim", async () => {
      const aiInvocation = { turnId: "turn-reduce", invocationReason: "reduction test", model: "mock" };
      try {
        await gateway.handleToolsCall("test/dangerous_tool", {}, "agent:blocked", undefined, aiInvocation);
      } catch (err: unknown) {
        const record = (err as { auditRecord: { parties?: Array<{ party: string; role: string; scope: string[] }>; aiInvocation?: { turnId?: string } } }).auditRecord;
        const allWitnessedFields = record.parties
          ?.filter(p => p.role === "witness")
          .flatMap(p => p.scope) ?? [];
        const allAssertedFields = record.parties
          ?.filter(p => p.role === "asserter")
          .flatMap(p => p.scope) ?? [];
        expect(allWitnessedFields.length).toBeGreaterThan(0);
        expect(allAssertedFields.length).toBeGreaterThan(0);
        expect(allAssertedFields).toContain("aiInvocation");
        expect(allWitnessedFields).not.toContain("aiInvocation");
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

  // The digest was covered only by signer.test.ts and witness.test.ts, both of
  // which build records by hand with literal values such as "c".repeat(64).
  // Nothing asserted that the *gateway* puts a real digest on a record it
  // emits, so replacing the computeDecisionContextDigest call in gateway.ts
  // with an empty string broke no test. These tests close that gap: they read
  // the digest off a gateway-produced record and check it against the exported
  // function's own output.
  describe("decisionContextDigest on gateway-emitted records", () => {
    const DENIED_PRINCIPAL = "agent:blocked";
    const DENIED_TOOL = "test/dangerous_tool";

    async function digestFromDeniedCall(principal: string): Promise<string> {
      try {
        await gateway.handleToolsCall(DENIED_TOOL, {}, principal);
      } catch (err) {
        const record = (err as ToolCallError).auditRecord;
        expect(record, "denied call should carry an audit record").toBeDefined();
        return record.decisionContextDigest as string;
      }
      throw new Error(
        `expected ${DENIED_TOOL} to be denied for ${principal}; policy rule missing?`,
      );
    }

    it("stamps a real digest on a denied call, not a placeholder", async () => {
      const digest = await digestFromDeniedCall(DENIED_PRINCIPAL);

      expect(digest, "gateway emitted no decisionContextDigest").toBeDefined();
      expect(digest).not.toBe("");
      // SHA-256 hex. Catches an empty string, a truncation, or a literal.
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
    });

    it("is stable across identical calls and is a real digest, not a constant", async () => {
      const first = await digestFromDeniedCall(DENIED_PRINCIPAL);
      const second = await digestFromDeniedCall(DENIED_PRINCIPAL);

      // Same principal, same tool, same rule: the digest must reproduce. A
      // digest seeded with a timestamp or a random value would fail here.
      expect(second).toBe(first);

      // And it must not be the digest of an unrelated context, which is what a
      // hardcoded or default-constructed value would collapse to.
      const unrelated = computeDecisionContextDigest({
        principal: null,
        toolName: "",
        toolNamespace: "",
        toolUpstream: "",
        matchedRule: null,
        effect: "allow",
      });
      expect(first).not.toBe(unrelated);
    });

    it("changes with the principal, so it binds who was evaluated", async () => {
      const blocked = await digestFromDeniedCall(DENIED_PRINCIPAL);

      // A second denied principal must produce a different digest. If the
      // gateway ever stopped feeding the principal through, both would match.
      const otherGateway = new Gateway({
        ...testConfig,
        policy: {
          defaultEffect: "allow",
          rules: [{ effect: "deny", principals: ["agent:other"], tools: [DENIED_TOOL] }],
        },
      });
      await otherGateway.init();
      otherGateway.registerUpstreamTools("test-server", "test", [
        { name: "dangerous_tool", description: "A dangerous tool" },
      ]);

      let otherDigest: string | undefined;
      try {
        await otherGateway.handleToolsCall(DENIED_TOOL, {}, "agent:other");
      } catch (err) {
        otherDigest = (err as ToolCallError).auditRecord.decisionContextDigest as string;
      }
      await otherGateway.shutdown();

      expect(otherDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(otherDigest).not.toBe(blocked);
    });
  });
});

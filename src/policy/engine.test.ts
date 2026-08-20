import { describe, it, expect } from "vitest";
import { PolicyEngine, computeDecisionContextDigest } from "./engine.js";
import type { ToolEntry } from "../types.js";

const tool = (name: string, ns: string): ToolEntry => ({
  name: `${ns}/${name}`,
  originalName: name,
  namespace: ns,
  upstream: `${ns}-server`,
});

describe("PolicyEngine", () => {
  describe("default-allow", () => {
    const engine = new PolicyEngine("allow", [
      { effect: "deny", principals: ["agent:readonly-*"], tools: ["*/write_*", "*/delete_*"] },
      { effect: "deny", tools: ["admin/shutdown"] },
    ]);

    it("allows unmatched tools", () => {
      const decision = engine.evaluate("agent:dev", tool("read_data", "github"));
      expect(decision.allowed).toBe(true);
    });

    it("denies matching principal+tool pattern", () => {
      const decision = engine.evaluate("agent:readonly-bot", tool("write_file", "fs"));
      expect(decision.allowed).toBe(false);
    });

    it("allows write for non-readonly principal", () => {
      const decision = engine.evaluate("agent:admin", tool("write_file", "fs"));
      expect(decision.allowed).toBe(true);
    });

    it("denies tool pattern regardless of principal", () => {
      const decision = engine.evaluate("agent:admin", tool("shutdown", "admin"));
      expect(decision.allowed).toBe(false);
    });
  });

  describe("default-deny", () => {
    const engine = new PolicyEngine("deny", [
      { effect: "allow", principals: ["agent:trusted-*"], namespaces: ["github"] },
    ]);

    it("denies by default", () => {
      const decision = engine.evaluate("agent:unknown", tool("create_pr", "github"));
      expect(decision.allowed).toBe(false);
    });

    it("allows matching principal+namespace", () => {
      const decision = engine.evaluate("agent:trusted-ci", tool("create_pr", "github"));
      expect(decision.allowed).toBe(true);
    });

    it("denies trusted principal on wrong namespace", () => {
      const decision = engine.evaluate("agent:trusted-ci", tool("drop_table", "database"));
      expect(decision.allowed).toBe(false);
    });
  });

  describe("rate limiting", () => {
    it("allows calls within limit", () => {
      const engine = new PolicyEngine("allow", [
        { effect: "allow", principals: ["agent:bot"], rateLimit: { maxPerMinute: 3 } },
      ]);

      const t = tool("read", "api");
      engine.evaluate("agent:bot", t);
      engine.recordInvocation("agent:bot", t);
      engine.recordInvocation("agent:bot", t);
      engine.recordInvocation("agent:bot", t);

      const decision = engine.evaluate("agent:bot", t);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("rate limit");
    });
  });

  describe("filterTools", () => {
    const engine = new PolicyEngine("allow", [
      { effect: "deny", principals: ["agent:limited"], tools: ["*/dangerous_*"] },
    ]);

    it("removes denied tools from list", () => {
      const tools = [
        tool("safe_read", "fs"),
        tool("dangerous_delete", "fs"),
        tool("safe_write", "fs"),
      ];
      const filtered = engine.filterTools("agent:limited", tools);
      expect(filtered).toHaveLength(2);
      expect(filtered.map((t) => t.originalName)).not.toContain("dangerous_delete");
    });
  });

  describe("decisionContext", () => {
    const engine = new PolicyEngine("allow", [
      { effect: "deny", principals: ["agent:readonly-*"], tools: ["*/write_*"] },
    ]);

    it("returns decision context with evaluation", () => {
      const t = tool("write_file", "fs");
      const result = engine.evaluate("agent:readonly-bot", t);
      expect(result.decisionContext).toBeDefined();
      expect(result.decisionContext.principal).toBe("agent:readonly-bot");
      expect(result.decisionContext.toolName).toBe("fs/write_file");
      expect(result.decisionContext.toolNamespace).toBe("fs");
      expect(result.decisionContext.effect).toBe("deny");
      expect(result.decisionContext.matchedRule).toEqual({
        effect: "deny",
        principals: ["agent:readonly-*"],
        tools: ["*/write_*"],
      });
    });

    it("produces stable digest for same input", () => {
      const t = tool("write_file", "fs");
      const r1 = engine.evaluate("agent:readonly-bot", t);
      const r2 = engine.evaluate("agent:readonly-bot", t);
      const d1 = computeDecisionContextDigest(r1.decisionContext);
      const d2 = computeDecisionContextDigest(r2.decisionContext);
      expect(d1).toBe(d2);
      expect(d1).toHaveLength(64);
    });

    it("produces different digest for different principal", () => {
      const t = tool("read_data", "github");
      const r1 = engine.evaluate("agent:alpha", t);
      const r2 = engine.evaluate("agent:beta", t);
      const d1 = computeDecisionContextDigest(r1.decisionContext);
      const d2 = computeDecisionContextDigest(r2.decisionContext);
      expect(d1).not.toBe(d2);
    });

    it("includes null principal when undefined", () => {
      const t = tool("read_data", "github");
      const result = engine.evaluate(undefined, t);
      expect(result.decisionContext.principal).toBeNull();
    });
  });
});

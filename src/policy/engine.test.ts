import { describe, it, expect } from "vitest";
import { PolicyEngine } from "./engine.js";
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
});

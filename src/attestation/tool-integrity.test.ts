import { describe, it, expect } from "vitest";
import { ToolIntegrityMonitor } from "./tool-integrity.js";

describe("ToolIntegrityMonitor", () => {
  describe("computeDigest", () => {
    it("produces a deterministic SHA-256 hex digest", () => {
      const monitor = new ToolIntegrityMonitor();
      const digest = monitor.computeDigest({
        name: "read_file",
        description: "Read a file from the filesystem",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
        },
      });
      expect(digest).toMatch(/^[a-f0-9]{64}$/);

      const digest2 = monitor.computeDigest({
        name: "read_file",
        description: "Read a file from the filesystem",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
        },
      });
      expect(digest).toBe(digest2);
    });

    it("is key-order independent (JCS sorts keys)", () => {
      const monitor = new ToolIntegrityMonitor();
      const d1 = monitor.computeDigest({
        name: "tool",
        description: "desc",
        inputSchema: { type: "object", properties: { a: { type: "string" }, b: { type: "number" } } },
      });
      const d2 = monitor.computeDigest({
        name: "tool",
        description: "desc",
        inputSchema: { properties: { b: { type: "number" }, a: { type: "string" } }, type: "object" },
      });
      expect(d1).toBe(d2);
    });

    it("produces different digests for different descriptions", () => {
      const monitor = new ToolIntegrityMonitor();
      const d1 = monitor.computeDigest({ name: "tool", description: "version 1" });
      const d2 = monitor.computeDigest({ name: "tool", description: "version 2" });
      expect(d1).not.toBe(d2);
    });

    it("distinguishes absent vs null-valued fields", () => {
      const monitor = new ToolIntegrityMonitor();
      const absent = monitor.computeDigest({ name: "tool" });
      const nullDesc = monitor.computeDigest({ name: "tool", description: undefined });
      expect(absent).toBe(nullDesc);
    });

    it("handles annotations correctly", () => {
      const monitor = new ToolIntegrityMonitor();
      const withAnnotations = monitor.computeDigest({
        name: "tool",
        annotations: { readOnlyHint: true, destructiveHint: false },
      });
      const withFlipped = monitor.computeDigest({
        name: "tool",
        annotations: { readOnlyHint: false, destructiveHint: false },
      });
      expect(withAnnotations).not.toBe(withFlipped);
    });
  });

  describe("checkAndUpdate", () => {
    it("returns null on first observation (sets baseline)", () => {
      const monitor = new ToolIntegrityMonitor();
      const result = monitor.checkAndUpdate("ns/tool", "ns", {
        name: "tool",
        description: "original",
      });
      expect(result).toBeNull();
      expect(monitor.hasBaseline("ns/tool")).toBe(true);
    });

    it("returns null when tool has not changed", () => {
      const monitor = new ToolIntegrityMonitor();
      monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "same" });
      const result = monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "same" });
      expect(result).toBeNull();
    });

    it("returns drift event when definition changes", () => {
      const monitor = new ToolIntegrityMonitor();
      monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "v1" });
      const event = monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "v2" });

      expect(event).not.toBeNull();
      expect(event!.toolName).toBe("ns/tool");
      expect(event!.namespace).toBe("ns");
      expect(event!.previousDefinitionDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(event!.newDefinitionDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(event!.previousDefinitionDigest).not.toBe(event!.newDefinitionDigest);
    });

    it("detects flip-flop (A→B→A emits two drift events)", () => {
      const monitor = new ToolIntegrityMonitor();
      monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "A" });

      const drift1 = monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "B" });
      expect(drift1).not.toBeNull();

      const drift2 = monitor.checkAndUpdate("ns/tool", "ns", { name: "tool", description: "A" });
      expect(drift2).not.toBeNull();
      expect(drift2!.previousDefinitionDigest).toBe(drift1!.newDefinitionDigest);
    });

    it("tracks multiple tools independently", () => {
      const monitor = new ToolIntegrityMonitor();
      monitor.checkAndUpdate("ns/tool1", "ns", { name: "tool1", description: "v1" });
      monitor.checkAndUpdate("ns/tool2", "ns", { name: "tool2", description: "v1" });

      const drift = monitor.checkAndUpdate("ns/tool1", "ns", { name: "tool1", description: "v2" });
      const noDrift = monitor.checkAndUpdate("ns/tool2", "ns", { name: "tool2", description: "v1" });

      expect(drift).not.toBeNull();
      expect(noDrift).toBeNull();
      expect(monitor.getBaselineCount()).toBe(2);
    });
  });
});

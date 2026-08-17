import { describe, it, expect, beforeEach, vi } from "vitest";
import { Logger } from "./logger.js";
import type { LogLevel } from "./logger.js";

describe("Logger", () => {
  let lines: string[];
  let logger: Logger;

  beforeEach(() => {
    lines = [];
    logger = new Logger({
      component: "test",
      level: "debug",
      output: (line) => lines.push(line),
    });
  });

  describe("structured output", () => {
    it("outputs valid JSON lines", () => {
      logger.info("hello world");
      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]);
      expect(parsed).toHaveProperty("timestamp");
      expect(parsed).toHaveProperty("level", "info");
      expect(parsed).toHaveProperty("component", "test");
      expect(parsed).toHaveProperty("message", "hello world");
    });

    it("includes ISO 8601 timestamp", () => {
      logger.info("msg");
      const parsed = JSON.parse(lines[0]);
      expect(() => new Date(parsed.timestamp)).not.toThrow();
      expect(parsed.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it("includes arbitrary context fields", () => {
      logger.info("tool call", { tool: "my_tool", durationMs: 42, upstream: "server-a" });
      const parsed = JSON.parse(lines[0]);
      expect(parsed.tool).toBe("my_tool");
      expect(parsed.durationMs).toBe(42);
      expect(parsed.upstream).toBe("server-a");
    });
  });

  describe("log levels", () => {
    it("outputs debug messages when level is debug", () => {
      logger.debug("trace msg");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).level).toBe("debug");
    });

    it("outputs info messages", () => {
      logger.info("info msg");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).level).toBe("info");
    });

    it("outputs warn messages", () => {
      logger.warn("warning");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).level).toBe("warn");
    });

    it("outputs error messages", () => {
      logger.error("failure");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).level).toBe("error");
    });
  });

  describe("level filtering", () => {
    it("suppresses debug when level is info", () => {
      const infoLogger = new Logger({
        component: "test",
        level: "info",
        output: (line) => lines.push(line),
      });
      infoLogger.debug("should not appear");
      infoLogger.info("should appear");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).message).toBe("should appear");
    });

    it("suppresses info and debug when level is warn", () => {
      const warnLogger = new Logger({
        component: "test",
        level: "warn",
        output: (line) => lines.push(line),
      });
      warnLogger.debug("no");
      warnLogger.info("no");
      warnLogger.warn("yes");
      warnLogger.error("yes");
      expect(lines).toHaveLength(2);
    });

    it("only outputs error when level is error", () => {
      const errorLogger = new Logger({
        component: "test",
        level: "error",
        output: (line) => lines.push(line),
      });
      errorLogger.debug("no");
      errorLogger.info("no");
      errorLogger.warn("no");
      errorLogger.error("yes");
      expect(lines).toHaveLength(1);
    });
  });

  describe("child logger", () => {
    it("creates child with different component", () => {
      const child = logger.child({ component: "sub-system" });
      child.info("child message");
      const parsed = JSON.parse(lines[0]);
      expect(parsed.component).toBe("sub-system");
    });

    it("child inherits parent output", () => {
      const child = logger.child({ component: "child" });
      child.warn("from child");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).component).toBe("child");
    });
  });

  describe("default output", () => {
    it("writes to stderr by default", () => {
      const stderrWrite = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const defaultLogger = new Logger({ component: "default-test", level: "info" });
      defaultLogger.info("stderr test");
      expect(stderrWrite).toHaveBeenCalled();
      const written = stderrWrite.mock.calls[0][0] as string;
      expect(written).toContain("stderr test");
      expect(written.endsWith("\n")).toBe(true);
      stderrWrite.mockRestore();
    });
  });
});

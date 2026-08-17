import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  UpstreamManager,
  UpstreamUnavailableError,
  ConnectionTimeoutError,
} from "./upstream-manager.js";
import type { UpstreamConfig } from "../types.js";

// Mock the MCP SDK modules
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => {
  return {
    Client: vi.fn().mockImplementation(() => ({
      connect: vi.fn().mockResolvedValue(undefined),
      listTools: vi.fn().mockResolvedValue({
        tools: [
          { name: "tool_a", description: "Tool A" },
          { name: "tool_b", description: "Tool B" },
        ],
      }),
      callTool: vi.fn().mockResolvedValue({ content: [{ type: "text", text: "ok" }] }),
      ping: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    })),
  };
});

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: vi.fn().mockImplementation(() => ({})),
}));

vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: vi.fn().mockImplementation(() => ({})),
}));

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");

function createMockClient() {
  const mockClient = {
    connect: vi.fn().mockResolvedValue(undefined),
    listTools: vi.fn().mockResolvedValue({
      tools: [
        { name: "tool_a", description: "Tool A" },
        { name: "tool_b", description: "Tool B" },
      ],
    }),
    callTool: vi.fn().mockResolvedValue({ content: [{ type: "text", text: "ok" }] }),
    ping: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  };
  return mockClient;
}

const testUpstream: UpstreamConfig = {
  name: "test-upstream",
  namespace: "test",
  transport: { type: "stdio", command: "echo", args: [] },
};

describe("UpstreamManager", () => {
  let manager: UpstreamManager;
  let mockClient: ReturnType<typeof createMockClient>;

  beforeEach(() => {
    vi.useFakeTimers();
    manager = new UpstreamManager();
    mockClient = createMockClient();
    vi.mocked(Client).mockImplementation(() => mockClient as any);
  });

  afterEach(async () => {
    await manager.disconnectAll();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe("connect", () => {
    it("connects to an upstream and lists tools", async () => {
      const conn = await manager.connect(testUpstream);
      expect(conn.status.status).toBe("healthy");
      expect(conn.tools).toHaveLength(2);
      expect(conn.consecutiveFailures).toBe(0);
    });

    it("times out if connect takes too long", async () => {
      mockClient.connect.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 20_000)),
      );

      const promise = manager.connect(testUpstream, 100);
      vi.advanceTimersByTime(101);
      await expect(promise).rejects.toThrow(ConnectionTimeoutError);
      await expect(promise).rejects.toThrow("timed out after 100ms");
    });

    it("times out if listTools takes too long", async () => {
      mockClient.listTools.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 20_000)),
      );

      const promise = manager.connect(testUpstream, 100);
      // Attach rejection handler before advancing timers to prevent unhandled rejection
      const expectation = expect(promise).rejects.toThrow(ConnectionTimeoutError);
      await vi.advanceTimersByTimeAsync(101);
      await expectation;
    });

    it("uses default timeout of 10s", async () => {
      mockClient.connect.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 20_000)),
      );

      const promise = manager.connect(testUpstream);
      vi.advanceTimersByTime(10_001);
      await expect(promise).rejects.toThrow(ConnectionTimeoutError);
      await expect(promise).rejects.toThrow("10000ms");
    });
  });

  describe("callTool", () => {
    it("calls tool successfully and resets failure count", async () => {
      await manager.connect(testUpstream);
      const result = await manager.callTool("test-upstream", "tool_a", {});
      expect(result).toEqual({ content: [{ type: "text", text: "ok" }] });
    });

    it("throws UpstreamUnavailableError when upstream is unavailable", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;
      conn.status.status = "unavailable";
      conn.status.unavailableReason = "Health check failures";

      await expect(
        manager.callTool("test-upstream", "tool_a", {}),
      ).rejects.toThrow(UpstreamUnavailableError);

      await expect(
        manager.callTool("test-upstream", "tool_a", {}),
      ).rejects.toThrow('Upstream "test-upstream" is unavailable');
    });

    it("marks upstream degraded after 1-2 failures", async () => {
      await manager.connect(testUpstream);
      mockClient.callTool.mockRejectedValue(new Error("call failed"));

      await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("degraded");
      expect(conn.consecutiveFailures).toBe(1);
    });

    it("marks upstream unavailable after 3 consecutive failures", async () => {
      await manager.connect(testUpstream);
      mockClient.callTool.mockRejectedValue(new Error("call failed"));

      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("unavailable");
      expect(conn.consecutiveFailures).toBe(3);
    });

    it("resets consecutive failures on successful call", async () => {
      await manager.connect(testUpstream);

      // Fail twice
      mockClient.callTool.mockRejectedValueOnce(new Error("fail 1"));
      mockClient.callTool.mockRejectedValueOnce(new Error("fail 2"));

      await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.consecutiveFailures).toBe(2);

      // Succeed resets counter
      mockClient.callTool.mockResolvedValueOnce({ content: [] });
      await manager.callTool("test-upstream", "tool_a", {});
      expect(conn.consecutiveFailures).toBe(0);
      expect(conn.status.status).toBe("healthy");
    });
  });

  describe("health check transitions", () => {
    it("transitions healthy -> degraded on first ping failure", async () => {
      await manager.connect(testUpstream);
      mockClient.ping.mockRejectedValue(new Error("ping timeout"));

      manager.startHealthChecks(1000);
      await vi.advanceTimersByTimeAsync(1000);

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("degraded");
      expect(conn.consecutiveFailures).toBe(1);
    });

    it("transitions degraded -> unavailable after 3 consecutive ping failures", async () => {
      await manager.connect(testUpstream);
      mockClient.ping.mockRejectedValue(new Error("ping timeout"));

      manager.startHealthChecks(1000);

      // Tick 3 health check cycles
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(1000);

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("unavailable");
      expect(conn.consecutiveFailures).toBe(3);
    });

    it("transitions degraded -> healthy on successful ping", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;

      // Manually set degraded state
      conn.status.status = "degraded";
      conn.consecutiveFailures = 2;

      mockClient.ping.mockResolvedValue(undefined);
      manager.startHealthChecks(1000);
      await vi.advanceTimersByTimeAsync(1000);

      expect(conn.status.status).toBe("healthy");
      expect(conn.consecutiveFailures).toBe(0);
    });

    it("skips health checks for unavailable upstreams", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;
      conn.status.status = "unavailable";

      manager.startHealthChecks(1000);
      await vi.advanceTimersByTimeAsync(1000);

      // ping should not be called for unavailable upstreams
      expect(mockClient.ping).not.toHaveBeenCalled();
    });

    it("full cycle: healthy -> degraded -> unavailable -> healthy (via reconnect)", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("healthy");

      // Degrade
      mockClient.ping.mockRejectedValue(new Error("down"));
      manager.startHealthChecks(1000);
      await vi.advanceTimersByTimeAsync(1000);
      expect(conn.status.status).toBe("degraded");

      // Become unavailable
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(1000);
      expect(conn.status.status).toBe("unavailable");

      // Recover via reconnect
      mockClient.connect.mockResolvedValue(undefined);
      mockClient.listTools.mockResolvedValue({
        tools: [{ name: "tool_a", description: "Tool A" }],
      });

      await manager.reconnect("test-upstream");
      expect(conn.status.status).toBe("healthy");
      expect(conn.consecutiveFailures).toBe(0);
    });
  });

  describe("reconnection backoff", () => {
    it("schedules reconnection with exponential backoff on unavailable", async () => {
      await manager.connect(testUpstream);
      mockClient.callTool.mockRejectedValue(new Error("fail"));

      // Trigger 3 failures to become unavailable
      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("unavailable");
      expect(conn.reconnectTimer).toBeDefined();
    });

    it("uses 1s backoff on first reconnect attempt", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;

      // Make unavailable (triggers first scheduled reconnect)
      mockClient.callTool.mockRejectedValue(new Error("fail"));
      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      // Mock reconnect to succeed
      mockClient.connect.mockResolvedValue(undefined);
      mockClient.listTools.mockResolvedValue({ tools: [] });

      // Advance less than 1s - should not reconnect yet
      await vi.advanceTimersByTimeAsync(999);
      expect(conn.status.status).toBe("unavailable");

      // Advance to 1s - should trigger reconnect
      await vi.advanceTimersByTimeAsync(1);
      expect(conn.status.status).toBe("healthy");
    });

    it("doubles backoff on consecutive reconnect failures", async () => {
      await manager.connect(testUpstream);

      // Make unavailable
      mockClient.callTool.mockRejectedValue(new Error("fail"));
      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.status.status).toBe("unavailable");

      // First reconnect attempt fails after 1s
      mockClient.connect.mockRejectedValue(new Error("still down"));
      await vi.advanceTimersByTimeAsync(1000);
      expect(conn.reconnectAttempts).toBe(1);
      expect(conn.status.status).toBe("unavailable");

      // Second reconnect attempt should be at 2s
      await vi.advanceTimersByTimeAsync(1999);
      expect(conn.reconnectAttempts).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(conn.reconnectAttempts).toBe(2);

      // Third reconnect attempt should be at 4s
      await vi.advanceTimersByTimeAsync(3999);
      expect(conn.reconnectAttempts).toBe(2);
      await vi.advanceTimersByTimeAsync(1);
      expect(conn.reconnectAttempts).toBe(3);
    });

    it("caps backoff at 30s", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;

      // Make unavailable
      mockClient.callTool.mockRejectedValue(new Error("fail"));
      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      // Mock reconnect to keep failing
      mockClient.connect.mockRejectedValue(new Error("still down"));

      // Advance through several reconnect attempts to exceed 30s cap
      // Attempts: 1s, 2s, 4s, 8s, 16s, 30s (capped), 30s (capped)
      await vi.advanceTimersByTimeAsync(1000); // attempt 1 at 1s
      expect(conn.reconnectAttempts).toBe(1);

      await vi.advanceTimersByTimeAsync(2000); // attempt 2 at 2s
      expect(conn.reconnectAttempts).toBe(2);

      await vi.advanceTimersByTimeAsync(4000); // attempt 3 at 4s
      expect(conn.reconnectAttempts).toBe(3);

      await vi.advanceTimersByTimeAsync(8000); // attempt 4 at 8s
      expect(conn.reconnectAttempts).toBe(4);

      await vi.advanceTimersByTimeAsync(16000); // attempt 5 at 16s
      expect(conn.reconnectAttempts).toBe(5);

      // Next should be capped at 30s (2^5 = 32s > 30s)
      await vi.advanceTimersByTimeAsync(29999);
      expect(conn.reconnectAttempts).toBe(5);
      await vi.advanceTimersByTimeAsync(1);
      expect(conn.reconnectAttempts).toBe(6);
    });

    it("resets reconnect attempts on successful reconnect", async () => {
      await manager.connect(testUpstream);

      // Make unavailable
      mockClient.callTool.mockRejectedValue(new Error("fail"));
      for (let i = 0; i < 3; i++) {
        await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      }

      const conn = manager.getConnection("test-upstream")!;

      // First reconnect fails
      mockClient.connect.mockRejectedValue(new Error("still down"));
      await vi.advanceTimersByTimeAsync(1000);
      expect(conn.reconnectAttempts).toBe(1);

      // Second reconnect succeeds
      mockClient.connect.mockResolvedValue(undefined);
      mockClient.listTools.mockResolvedValue({ tools: [] });
      await vi.advanceTimersByTimeAsync(2000);
      expect(conn.reconnectAttempts).toBe(0);
      expect(conn.status.status).toBe("healthy");
    });
  });

  describe("timeout behavior", () => {
    it("throws ConnectionTimeoutError with upstream name and timeout value", async () => {
      mockClient.connect.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 60_000)),
      );

      const promise = manager.connect(testUpstream, 5000);
      vi.advanceTimersByTime(5001);

      await expect(promise).rejects.toThrow(ConnectionTimeoutError);
      try {
        vi.advanceTimersByTime(5001);
        await promise;
      } catch (err) {
        expect(err).toBeInstanceOf(ConnectionTimeoutError);
        expect((err as ConnectionTimeoutError).upstreamName).toBe("test-upstream");
        expect((err as ConnectionTimeoutError).timeoutMs).toBe(5000);
      }
    });

    it("does not mark as unavailable if connect times out (no prior connection)", async () => {
      mockClient.connect.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 60_000)),
      );

      const promise = manager.connect(testUpstream, 100);
      vi.advanceTimersByTime(101);
      await expect(promise).rejects.toThrow();

      // No connection was stored
      expect(manager.getConnection("test-upstream")).toBeUndefined();
    });

    it("connect timeout is configurable per-call", async () => {
      mockClient.connect.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 5000)),
      );

      // Short timeout fails
      const shortPromise = manager.connect(testUpstream, 50);
      vi.advanceTimersByTime(51);
      await expect(shortPromise).rejects.toThrow(ConnectionTimeoutError);

      // Long timeout succeeds
      const longPromise = manager.connect(testUpstream, 10_000);
      vi.advanceTimersByTime(5000);
      const conn = await longPromise;
      expect(conn.status.status).toBe("healthy");
    });
  });

  describe("graceful degradation", () => {
    it("returns clear error with upstream name when upstream is unavailable", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;
      conn.status.status = "unavailable";
      conn.status.unavailableReason = "Connection lost after 3 ping failures";

      try {
        await manager.callTool("test-upstream", "tool_a", {});
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(UpstreamUnavailableError);
        const error = err as UpstreamUnavailableError;
        expect(error.upstreamName).toBe("test-upstream");
        expect(error.reason).toBe("Connection lost after 3 ping failures");
        expect(error.message).toContain("test-upstream");
        expect(error.message).toContain("unavailable");
      }
    });

    it("does not attempt tool call when upstream is unavailable", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;
      conn.status.status = "unavailable";

      await expect(manager.callTool("test-upstream", "tool_a", {})).rejects.toThrow();
      expect(mockClient.callTool).not.toHaveBeenCalled();
    });

    it("allows calls after upstream recovers", async () => {
      await manager.connect(testUpstream);
      const conn = manager.getConnection("test-upstream")!;

      // Make unavailable
      conn.status.status = "unavailable";

      // Reconnect successfully
      mockClient.connect.mockResolvedValue(undefined);
      mockClient.listTools.mockResolvedValue({ tools: [{ name: "tool_a" }] });
      await manager.reconnect("test-upstream");

      expect(conn.status.status).toBe("healthy");

      // Call should work now
      mockClient.callTool.mockResolvedValue({ content: [] });
      const result = await manager.callTool("test-upstream", "tool_a", {});
      expect(result).toEqual({ content: [] });
    });
  });

  describe("stopHealthChecks", () => {
    it("stops the health check interval", async () => {
      await manager.connect(testUpstream);
      mockClient.ping.mockRejectedValue(new Error("down"));

      manager.startHealthChecks(1000);
      await vi.advanceTimersByTimeAsync(1000);

      const conn = manager.getConnection("test-upstream")!;
      expect(conn.consecutiveFailures).toBe(1);

      manager.stopHealthChecks();
      await vi.advanceTimersByTimeAsync(5000);

      // Failures should not have increased
      expect(conn.consecutiveFailures).toBe(1);
    });
  });

  describe("disconnectAll", () => {
    it("cleans up all timers and connections", async () => {
      await manager.connect(testUpstream);
      manager.startHealthChecks(1000);

      const conn = manager.getConnection("test-upstream")!;
      conn.status.status = "unavailable";

      await manager.disconnectAll();
      expect(manager.getConnection("test-upstream")).toBeUndefined();
      expect(manager.getAllStatuses()).toHaveLength(0);
    });
  });
});

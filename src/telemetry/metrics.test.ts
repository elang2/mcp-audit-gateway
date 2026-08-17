import { describe, it, expect, beforeEach, vi } from "vitest";
import { metrics } from "@opentelemetry/api";
import { GatewayMetrics } from "./metrics.js";
import type { TelemetryConfig } from "../types.js";

const testConfig: TelemetryConfig = {
  enabled: true,
  serviceName: "test-gateway",
  sampleRate: 1.0,
};

describe("GatewayMetrics", () => {
  let gatewayMetrics: GatewayMetrics;

  beforeEach(() => {
    gatewayMetrics = new GatewayMetrics(testConfig);
  });

  describe("construction", () => {
    it("creates all metric instruments", () => {
      expect(gatewayMetrics.toolCallsTotal).toBeDefined();
      expect(gatewayMetrics.toolCallDurationMs).toBeDefined();
      expect(gatewayMetrics.upstreamStatus).toBeDefined();
      expect(gatewayMetrics.policyDenialsTotal).toBeDefined();
    });
  });

  describe("recordToolCall", () => {
    it("increments tool_calls_total counter without throwing", () => {
      expect(() =>
        gatewayMetrics.recordToolCall({
          namespace: "test",
          tool: "test/my_tool",
          principal: "agent:user1",
          success: "true",
        }),
      ).not.toThrow();
    });

    it("accepts different label combinations", () => {
      expect(() =>
        gatewayMetrics.recordToolCall({
          namespace: "prod",
          tool: "prod/fetch_data",
          principal: "anonymous",
          success: "false",
        }),
      ).not.toThrow();
    });
  });

  describe("recordDuration", () => {
    it("records duration histogram without throwing", () => {
      expect(() =>
        gatewayMetrics.recordDuration(42.5, {
          namespace: "test",
          upstream: "my-server",
        }),
      ).not.toThrow();
    });

    it("handles zero duration", () => {
      expect(() =>
        gatewayMetrics.recordDuration(0, {
          namespace: "test",
          upstream: "fast-server",
        }),
      ).not.toThrow();
    });

    it("handles large durations", () => {
      expect(() =>
        gatewayMetrics.recordDuration(30000, {
          namespace: "test",
          upstream: "slow-server",
        }),
      ).not.toThrow();
    });
  });

  describe("setUpstreamStatus", () => {
    it("records gauge value for healthy status", () => {
      expect(() =>
        gatewayMetrics.setUpstreamStatus("my-upstream", "healthy", 1),
      ).not.toThrow();
    });

    it("records gauge value for unhealthy status", () => {
      expect(() =>
        gatewayMetrics.setUpstreamStatus("my-upstream", "unavailable", 0),
      ).not.toThrow();
    });
  });

  describe("recordPolicyDenial", () => {
    it("increments policy_denials_total counter without throwing", () => {
      expect(() =>
        gatewayMetrics.recordPolicyDenial({
          principal: "agent:blocked",
          tool: "test/dangerous_tool",
          reason: "unauthorized",
        }),
      ).not.toThrow();
    });

    it("records denial with rate limit reason", () => {
      expect(() =>
        gatewayMetrics.recordPolicyDenial({
          principal: "agent:heavy",
          tool: "test/expensive_tool",
          reason: "rate_limit_exceeded",
        }),
      ).not.toThrow();
    });
  });

  describe("with custom MeterProvider", () => {
    it("uses the global meter provider", () => {
      const getMeterSpy = vi.spyOn(metrics, "getMeter");
      new GatewayMetrics(testConfig);
      expect(getMeterSpy).toHaveBeenCalledWith("mcp-audit-gateway", "0.1.0");
      getMeterSpy.mockRestore();
    });
  });
});

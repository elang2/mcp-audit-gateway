import { metrics, ValueType } from "@opentelemetry/api";
import type { Counter, Histogram, Gauge, Meter } from "@opentelemetry/api";
import type { TelemetryConfig } from "../types.js";

const METER_NAME = "mcp-audit-gateway";

export interface MetricLabels {
  toolCall: { namespace: string; tool: string; principal: string; success: string };
  duration: { namespace: string; upstream: string };
  upstreamStatus: { upstream: string; status: string };
  policyDenial: { principal: string; tool: string; reason: string };
}

export class GatewayMetrics {
  private meter: Meter;
  private _toolCallsTotal: Counter;
  private _toolCallDurationMs: Histogram;
  private _upstreamStatus: Gauge;
  private _policyDenialsTotal: Counter;
  private _enabled: boolean;

  constructor(config: TelemetryConfig) {
    this._enabled = config.enabled;
    this.meter = metrics.getMeter(METER_NAME, "0.1.0");

    this._toolCallsTotal = this.meter.createCounter("mcp.gateway.tool_calls_total", {
      description: "Total number of tool calls processed by the gateway",
      valueType: ValueType.INT,
    });

    this._toolCallDurationMs = this.meter.createHistogram("mcp.gateway.tool_call_duration_ms", {
      description: "Duration of tool call execution in milliseconds",
      unit: "ms",
      valueType: ValueType.DOUBLE,
    });

    this._upstreamStatus = this.meter.createGauge("mcp.gateway.upstream_status", {
      description: "Current status of upstream servers (1=healthy, 0=unhealthy)",
      valueType: ValueType.INT,
    });

    this._policyDenialsTotal = this.meter.createCounter("mcp.gateway.policy_denials_total", {
      description: "Total number of policy denials",
      valueType: ValueType.INT,
    });
  }

  recordToolCall(labels: MetricLabels["toolCall"]): void {
    if (!this._enabled) return;
    this._toolCallsTotal.add(1, labels);
  }

  recordDuration(durationMs: number, labels: MetricLabels["duration"]): void {
    if (!this._enabled) return;
    this._toolCallDurationMs.record(durationMs, labels);
  }

  setUpstreamStatus(upstream: string, status: string, value: number): void {
    if (!this._enabled) return;
    this._upstreamStatus.record(value, { upstream, status });
  }

  recordPolicyDenial(labels: MetricLabels["policyDenial"]): void {
    if (!this._enabled) return;
    this._policyDenialsTotal.add(1, labels);
  }

  get toolCallsTotal(): Counter {
    return this._toolCallsTotal;
  }

  get toolCallDurationMs(): Histogram {
    return this._toolCallDurationMs;
  }

  get upstreamStatus(): Gauge {
    return this._upstreamStatus;
  }

  get policyDenialsTotal(): Counter {
    return this._policyDenialsTotal;
  }
}

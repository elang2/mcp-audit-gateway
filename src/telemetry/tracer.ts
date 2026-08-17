import { trace, context, SpanKind, SpanStatusCode, propagation, INVALID_SPAN_CONTEXT } from "@opentelemetry/api";
import type { Span, Tracer, SpanContext } from "@opentelemetry/api";
import type { TelemetryConfig } from "../types.js";

const NOOP_SPAN: Span = {
  spanContext(): SpanContext { return INVALID_SPAN_CONTEXT; },
  setAttribute() { return this; },
  setAttributes() { return this; },
  addEvent() { return this; },
  addLink() { return this; },
  addLinks() { return this; },
  setStatus() { return this; },
  updateName() { return this; },
  end() {},
  isRecording() { return false; },
  recordException() {},
};

const TRACER_NAME = "mcp-audit-gateway";

export class GatewayTracer {
  private tracer: Tracer;

  constructor(private config: TelemetryConfig) {
    this.tracer = trace.getTracer(TRACER_NAME, "0.1.0");
  }

  startRouteSpan(
    method: string,
    toolName: string | undefined,
    upstream: string,
    traceContext?: { traceparent?: string; tracestate?: string },
  ): Span {
    if (!this.config.enabled) return NOOP_SPAN;

    const spanName = toolName
      ? `mcp.gateway/route ${upstream}`
      : `mcp.${method}`;

    const parentContext = traceContext?.traceparent
      ? this.extractContext(traceContext)
      : context.active();

    const span = this.tracer.startSpan(
      spanName,
      {
        kind: SpanKind.INTERNAL,
        attributes: {
          "mcp.method": method,
          "mcp.gateway.name": this.config.serviceName,
          "mcp.gateway.route.target": upstream,
        },
      },
      parentContext,
    );

    if (toolName) {
      span.setAttribute("mcp.tool.name", toolName);
    }

    return span;
  }

  endSpan(span: Span, success: boolean, errorCode?: number): void {
    if (!success) {
      span.setStatus({ code: SpanStatusCode.ERROR });
      if (errorCode != null) {
        span.setAttribute("mcp.error.code", errorCode);
      }
    }
    span.end();
  }

  recordDuration(span: Span, durationMs: number): void {
    span.setAttribute("mcp.duration_ms", durationMs);
  }

  getTraceParent(span: Span): string {
    const spanContext = span.spanContext();
    const flags = spanContext.traceFlags.toString(16).padStart(2, "0");
    return `00-${spanContext.traceId}-${spanContext.spanId}-${flags}`;
  }

  private extractContext(traceContext: { traceparent?: string; tracestate?: string }) {
    const carrier: Record<string, string> = {};
    if (traceContext.traceparent) carrier["traceparent"] = traceContext.traceparent;
    if (traceContext.tracestate) carrier["tracestate"] = traceContext.tracestate;
    return propagation.extract(context.active(), carrier);
  }
}

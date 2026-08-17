import type {
  GatewayConfig,
  UpstreamConfig,
  UpstreamStatus,
  ToolEntry,
  AuditRecord,
} from "../types.js";
import { PolicyEngine } from "../policy/engine.js";
import { AuditLog } from "../attestation/audit-log.js";
import { createSigner } from "../attestation/signer.js";
import { GatewayTracer } from "../telemetry/tracer.js";
import { GatewayMetrics } from "../telemetry/metrics.js";
import { UpstreamManager } from "./upstream-manager.js";

export class Gateway {
  private toolCatalog: Map<string, ToolEntry> = new Map();
  private manualStatuses?: Map<string, UpstreamStatus>;
  private policyEngine: PolicyEngine;
  private auditLog: AuditLog;
  private tracer: GatewayTracer;
  private metrics: GatewayMetrics;
  private upstreamManager: UpstreamManager;

  constructor(private config: GatewayConfig) {
    this.policyEngine = new PolicyEngine(
      config.policy.defaultEffect,
      config.policy.rules,
    );

    const signer = createSigner(config.attestation);
    this.auditLog = new AuditLog(
      config.auditLog.path,
      signer,
      config.auditLog.rotateAfterMb * 1024 * 1024,
    );

    this.tracer = new GatewayTracer(config.telemetry);
    this.metrics = new GatewayMetrics(config.telemetry);
    this.upstreamManager = new UpstreamManager();
  }

  async init(): Promise<void> {
    await this.auditLog.init();
    for (const upstream of this.config.upstreams) {
      await this.connectUpstream(upstream);
    }
  }

  private async connectUpstream(upstream: UpstreamConfig): Promise<void> {
    try {
      const conn = await this.upstreamManager.connect(upstream);
      this.registerUpstreamTools(
        upstream.name,
        upstream.namespace,
        conn.tools,
      );
    } catch (err) {
      console.error(`Failed to connect to upstream ${upstream.name}: ${err}`);
    }
  }

  async handleToolsList(
    principal?: string,
    _meta?: Record<string, unknown>,
  ): Promise<{ tools: unknown[]; _meta?: Record<string, unknown> }> {
    const allTools = Array.from(this.toolCatalog.values());
    const filtered = this.policyEngine.filterTools(principal, allTools);

    const tools = filtered.map((entry) => ({
      name: entry.name,
      description: entry.description,
      inputSchema: entry.inputSchema,
      annotations: entry.annotations,
      _meta: {
        "x-gateway-routing/v1": {
          upstream: entry.upstream,
          namespace: entry.namespace,
        },
      },
    }));

    return {
      tools,
      _meta: {
        "x-gateway-routing/v1": {
          filteringApplied: true,
          identityResolved: principal ?? "anonymous",
          totalToolsPreFilter: this.toolCatalog.size,
          totalToolsPostFilter: filtered.length,
        },
      },
    };
  }

  async handleToolsCall(
    toolName: string,
    args: Record<string, unknown>,
    principal?: string,
    traceContext?: { traceparent?: string; tracestate?: string },
  ): Promise<{ result: unknown; auditRecord: AuditRecord }> {
    const startTime = Date.now();
    const tool = this.toolCatalog.get(toolName);

    if (!tool) {
      const record = await this.auditLog.record("tools/call", {
        toolName,
        principal,
        durationMs: Date.now() - startTime,
        success: false,
        errorCode: -32602,
      });
      throw new ToolCallError(-32602, `Unknown tool: ${toolName}`, record);
    }

    const decision = this.policyEngine.evaluate(principal, tool);
    if (!decision.allowed) {
      this.metrics.recordPolicyDenial({
        principal: principal ?? "anonymous",
        tool: toolName,
        reason: decision.reason ?? "unauthorized",
      });
      const record = await this.auditLog.record("tools/call", {
        toolName,
        namespace: tool.namespace,
        upstream: tool.upstream,
        principal,
        durationMs: Date.now() - startTime,
        success: false,
        errorCode: -32603,
      });
      throw new ToolCallError(
        -32603,
        decision.reason ?? "unauthorized",
        record,
      );
    }

    const span = this.tracer.startRouteSpan(
      "tools/call",
      toolName,
      tool.upstream,
      traceContext,
    );

    try {
      this.policyEngine.recordInvocation(principal, tool);

      const result = await this.upstreamManager.callTool(
        tool.upstream,
        tool.originalName,
        args,
      );
      const durationMs = Date.now() - startTime;

      this.tracer.recordDuration(span, durationMs);
      this.tracer.endSpan(span, true);

      this.metrics.recordToolCall({
        namespace: tool.namespace,
        tool: toolName,
        principal: principal ?? "anonymous",
        success: "true",
      });
      this.metrics.recordDuration(durationMs, {
        namespace: tool.namespace,
        upstream: tool.upstream,
      });

      const record = await this.safeAuditRecord("tools/call", {
        toolName,
        namespace: tool.namespace,
        upstream: tool.upstream,
        principal,
        durationMs,
        success: true,
      });

      return { result, auditRecord: record };
    } catch (err) {
      const durationMs = Date.now() - startTime;
      this.tracer.recordDuration(span, durationMs);
      this.tracer.endSpan(span, false);

      this.metrics.recordToolCall({
        namespace: tool.namespace,
        tool: toolName,
        principal: principal ?? "anonymous",
        success: "false",
      });
      this.metrics.recordDuration(durationMs, {
        namespace: tool.namespace,
        upstream: tool.upstream,
      });

      if (err instanceof ToolCallError) throw err;

      const record = await this.safeAuditRecord("tools/call", {
        toolName,
        namespace: tool.namespace,
        upstream: tool.upstream,
        principal,
        durationMs,
        success: false,
        errorCode: -32603,
      });
      throw new ToolCallError(-32603, "Upstream server error", record);
    }
  }

  getStatus(): {
    gateway: { status: string; version: string };
    upstreams: UpstreamStatus[];
    aggregate: {
      totalUpstreams: number;
      healthyUpstreams: number;
      degradedUpstreams: number;
      unavailableUpstreams: number;
      totalTools: number;
    };
  } {
    const managed = this.upstreamManager.getAllStatuses();
    const manual = this.manualStatuses ? Array.from(this.manualStatuses.values()) : [];
    const upstreams = managed.length > 0 ? managed : manual;
    return {
      gateway: {
        status: "healthy",
        version: this.config.version,
      },
      upstreams,
      aggregate: {
        totalUpstreams: upstreams.length,
        healthyUpstreams: upstreams.filter((u) => u.status === "healthy").length,
        degradedUpstreams: upstreams.filter((u) => u.status === "degraded").length,
        unavailableUpstreams: upstreams.filter((u) => u.status === "unavailable").length,
        totalTools: this.toolCatalog.size,
      },
    };
  }

  getServerDiscover(): Record<string, unknown> {
    return {
      name: this.config.name,
      version: this.config.version,
      protocol: "2025-03-26",
      capabilities: {
        tools: { listChanged: true },
        gateway: {
          namespacing: true,
          filtering: true,
          routing: true,
          healthReporting: true,
          attestation: this.config.attestation.enabled,
          upstreamCount: this.config.upstreams.length,
        },
      },
      extensions: ["x-gateway-routing/v1", "x-gateway-attestation/v1"],
    };
  }

  registerUpstreamTools(
    upstreamName: string,
    namespace: string,
    tools: Array<{
      name: string;
      description?: string;
      inputSchema?: unknown;
      annotations?: Record<string, unknown>;
    }>,
  ): void {
    for (const tool of tools) {
      const namespacedName = `${namespace}/${tool.name}`;
      const entry: ToolEntry = {
        name: namespacedName,
        originalName: tool.name,
        namespace,
        upstream: upstreamName,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      };
      this.toolCatalog.set(namespacedName, entry);
    }

    if (!this.manualStatuses) this.manualStatuses = new Map();
    this.manualStatuses.set(upstreamName, {
      name: upstreamName,
      namespace,
      status: "healthy",
      toolCount: tools.length,
      lastSuccessfulContact: new Date().toISOString(),
    });

    this.metrics.setUpstreamStatus(upstreamName, "healthy", 1);
  }

  private async safeAuditRecord(
    method: string,
    opts: Parameters<AuditLog["record"]>[1],
  ): Promise<AuditRecord> {
    try {
      return await this.auditLog.record(method, opts);
    } catch (err) {
      console.error(`Audit log write failed: ${err}`);
      return {
        id: "unrecorded",
        timestamp: new Date().toISOString(),
        method,
        ...opts,
        attestation: undefined,
      };
    }
  }

  async shutdown(): Promise<void> {
    await this.upstreamManager.disconnectAll();
  }
}

export class ToolCallError extends Error {
  constructor(
    public code: number,
    message: string,
    public auditRecord: AuditRecord,
  ) {
    super(message);
    this.name = "ToolCallError";
  }
}

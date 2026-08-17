import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { UpstreamConfig, UpstreamStatus } from "../types.js";

export interface UpstreamConnection {
  config: UpstreamConfig;
  client: Client;
  status: UpstreamStatus;
  tools: Array<{
    name: string;
    description?: string;
    inputSchema?: unknown;
    annotations?: Record<string, unknown>;
  }>;
  consecutiveFailures: number;
  reconnectAttempts: number;
  reconnectTimer?: ReturnType<typeof setTimeout>;
}

export class UpstreamManager {
  private connections: Map<string, UpstreamConnection> = new Map();
  private healthCheckInterval?: ReturnType<typeof setInterval>;
  private static readonly MAX_CONSECUTIVE_FAILURES = 3;
  private static readonly DEFAULT_TIMEOUT_MS = 10_000;
  private static readonly MAX_BACKOFF_MS = 30_000;
  private static readonly BASE_BACKOFF_MS = 1_000;

  async connect(
    upstream: UpstreamConfig,
    timeoutMs: number = UpstreamManager.DEFAULT_TIMEOUT_MS,
  ): Promise<UpstreamConnection> {
    const client = new Client(
      { name: "mcp-audit-gateway", version: "0.1.0" },
      { capabilities: {} },
    );

    const transport = this.createTransport(upstream);

    await this.withTimeout(client.connect(transport), timeoutMs, upstream.name);

    let tools: UpstreamConnection["tools"];
    try {
      const toolsResult = await this.withTimeout(
        client.listTools(),
        timeoutMs,
        upstream.name,
      );
      tools = toolsResult.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
        annotations: t.annotations as Record<string, unknown> | undefined,
      }));
    } catch (err) {
      try {
        await client.close();
      } catch {
        // best effort
      }
      throw err;
    }

    const connection: UpstreamConnection = {
      config: upstream,
      client,
      status: {
        name: upstream.name,
        namespace: upstream.namespace,
        status: "healthy",
        toolCount: tools.length,
        lastSuccessfulContact: new Date().toISOString(),
      },
      tools,
      consecutiveFailures: 0,
      reconnectAttempts: 0,
    };

    this.connections.set(upstream.name, connection);
    return connection;
  }

  async callTool(
    upstreamName: string,
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const conn = this.connections.get(upstreamName);
    if (!conn) {
      throw new Error(`Upstream not connected: ${upstreamName}`);
    }

    if (conn.status.status === "unavailable") {
      throw new UpstreamUnavailableError(
        upstreamName,
        conn.status.unavailableReason ?? "Upstream is unavailable",
      );
    }

    try {
      const result = await conn.client.callTool({ name: toolName, arguments: args });
      conn.status.lastSuccessfulContact = new Date().toISOString();
      conn.status.status = "healthy";
      conn.consecutiveFailures = 0;
      return result;
    } catch (err) {
      conn.consecutiveFailures++;
      if (conn.consecutiveFailures >= UpstreamManager.MAX_CONSECUTIVE_FAILURES) {
        this.markUnavailable(conn, String(err));
      } else {
        conn.status.status = "degraded";
        conn.status.degradedReason = String(err);
      }
      throw err;
    }
  }

  startHealthChecks(intervalMs: number): void {
    this.stopHealthChecks();
    this.healthCheckInterval = setInterval(() => {
      void this.runHealthChecks();
    }, intervalMs);
  }

  stopHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = undefined;
    }
  }

  async reconnect(upstreamName: string): Promise<void> {
    const conn = this.connections.get(upstreamName);
    if (!conn) {
      throw new Error(`Upstream not found: ${upstreamName}`);
    }

    if (conn.reconnectTimer) {
      clearTimeout(conn.reconnectTimer);
      conn.reconnectTimer = undefined;
    }

    try {
      try {
        await conn.client.close();
      } catch {
        // best effort
      }

      const client = new Client(
        { name: "mcp-audit-gateway", version: "0.1.0" },
        { capabilities: {} },
      );
      const transport = this.createTransport(conn.config);
      await this.withTimeout(
        client.connect(transport),
        UpstreamManager.DEFAULT_TIMEOUT_MS,
        upstreamName,
      );

      const toolsResult = await this.withTimeout(
        client.listTools(),
        UpstreamManager.DEFAULT_TIMEOUT_MS,
        upstreamName,
      );
      const tools = toolsResult.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
        annotations: t.annotations as Record<string, unknown> | undefined,
      }));

      conn.client = client;
      conn.tools = tools;
      conn.status.status = "healthy";
      conn.status.toolCount = tools.length;
      conn.status.lastSuccessfulContact = new Date().toISOString();
      conn.status.unavailableReason = undefined;
      conn.status.degradedReason = undefined;
      conn.consecutiveFailures = 0;
      conn.reconnectAttempts = 0;
    } catch (err) {
      conn.reconnectAttempts++;
      this.scheduleReconnect(conn);
      throw err;
    }
  }

  getConnection(name: string): UpstreamConnection | undefined {
    return this.connections.get(name);
  }

  getAllStatuses(): UpstreamStatus[] {
    return Array.from(this.connections.values()).map((c) => c.status);
  }

  async disconnectAll(): Promise<void> {
    this.stopHealthChecks();
    for (const conn of this.connections.values()) {
      if (conn.reconnectTimer) {
        clearTimeout(conn.reconnectTimer);
      }
      try {
        await conn.client.close();
      } catch {
        // best effort
      }
    }
    this.connections.clear();
  }

  private async runHealthChecks(): Promise<void> {
    for (const conn of this.connections.values()) {
      if (conn.status.status === "unavailable") {
        continue;
      }

      try {
        await conn.client.ping();
        conn.status.lastSuccessfulContact = new Date().toISOString();
        conn.consecutiveFailures = 0;
        if (conn.status.status === "degraded") {
          conn.status.status = "healthy";
          conn.status.degradedReason = undefined;
        }
      } catch (err) {
        conn.consecutiveFailures++;
        if (conn.consecutiveFailures >= UpstreamManager.MAX_CONSECUTIVE_FAILURES) {
          this.markUnavailable(conn, `Health check failed: ${err}`);
        } else {
          conn.status.status = "degraded";
          conn.status.degradedReason = `Health check failed: ${err}`;
        }
      }
    }
  }

  private markUnavailable(conn: UpstreamConnection, reason: string): void {
    conn.status.status = "unavailable";
    conn.status.unavailableReason = reason;
    conn.status.degradedReason = undefined;
    this.scheduleReconnect(conn);
  }

  private scheduleReconnect(conn: UpstreamConnection): void {
    if (conn.reconnectTimer) {
      clearTimeout(conn.reconnectTimer);
    }

    const backoffMs = this.calculateBackoff(conn.reconnectAttempts);
    conn.reconnectTimer = setTimeout(() => {
      void this.reconnect(conn.config.name).catch(() => {});
    }, backoffMs);
  }

  private calculateBackoff(attempt: number): number {
    const exponential = UpstreamManager.BASE_BACKOFF_MS * Math.pow(2, attempt);
    return Math.min(exponential, UpstreamManager.MAX_BACKOFF_MS);
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    upstreamName: string,
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new ConnectionTimeoutError(
            upstreamName,
            timeoutMs,
          ),
        );
      }, timeoutMs);
    });

    try {
      const result = await Promise.race([promise, timeoutPromise]);
      clearTimeout(timer!);
      return result;
    } catch (err) {
      clearTimeout(timer!);
      throw err;
    }
  }

  private createTransport(upstream: UpstreamConfig) {
    if (upstream.transport.type === "stdio") {
      return new StdioClientTransport({
        command: upstream.transport.command,
        args: upstream.transport.args,
        env: upstream.transport.env,
      });
    }

    return new StreamableHTTPClientTransport(
      new URL(upstream.transport.url),
      upstream.transport.headers ? { requestInit: { headers: upstream.transport.headers } } : undefined,
    );
  }
}

export class UpstreamUnavailableError extends Error {
  constructor(
    public readonly upstreamName: string,
    public readonly reason: string,
  ) {
    super(
      `Upstream "${upstreamName}" is unavailable: ${reason}`,
    );
    this.name = "UpstreamUnavailableError";
  }
}

export class ConnectionTimeoutError extends Error {
  constructor(
    public readonly upstreamName: string,
    public readonly timeoutMs: number,
  ) {
    super(
      `Connection to upstream "${upstreamName}" timed out after ${timeoutMs}ms`,
    );
    this.name = "ConnectionTimeoutError";
  }
}

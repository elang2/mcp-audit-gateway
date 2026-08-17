import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { Gateway, ToolCallError } from "./gateway.js";

export interface McpServerAdapterOptions {
  name: string;
  version: string;
  resolvePrincipal?: (meta?: Record<string, unknown>) => string | undefined;
}

export class McpServerAdapter {
  private server: Server;
  private gateway: Gateway;
  private resolvePrincipal?: (meta?: Record<string, unknown>) => string | undefined;

  constructor(gateway: Gateway, options: McpServerAdapterOptions) {
    this.gateway = gateway;
    this.resolvePrincipal = options.resolvePrincipal;

    const discover = gateway.getServerDiscover();
    const gatewayCapabilities = (discover.capabilities as Record<string, unknown>)?.gateway;

    this.server = new Server(
      { name: options.name, version: options.version },
      {
        capabilities: {
          tools: { listChanged: true },
          experimental: {
            "x-gateway-routing/v1": gatewayCapabilities ?? {},
            "x-gateway-attestation/v1": { enabled: true },
          },
        },
      },
    );

    this.registerHandlers();
  }

  async connect(transport: Transport): Promise<void> {
    await this.server.connect(transport);
  }

  async close(): Promise<void> {
    await this.server.close();
  }

  getServer(): Server {
    return this.server;
  }

  private registerHandlers(): void {
    this.server.setRequestHandler(
      ListToolsRequestSchema,
      async (request) => {
        const principal = this.extractPrincipal(request.params?._meta);
        const listResult = await this.gateway.handleToolsList(principal);

        return {
          tools: listResult.tools.map((tool: any) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema ?? { type: "object" as const },
            annotations: tool.annotations,
          })),
          _meta: listResult._meta,
        };
      },
    );

    this.server.setRequestHandler(
      CallToolRequestSchema,
      async (request) => {
        const principal = this.extractPrincipal(request.params?._meta);
        const traceContext = this.extractTraceContext(request.params?._meta);
        const toolName = request.params.name;
        const args = (request.params.arguments ?? {}) as Record<string, unknown>;

        try {
          const { result, auditRecord } = await this.gateway.handleToolsCall(
            toolName,
            args,
            principal,
            traceContext,
          );

          const upstreamResult = result as {
            content?: Array<{ type: string; text?: string; [key: string]: unknown }>;
            isError?: boolean;
          };

          return {
            content: upstreamResult?.content ?? [{ type: "text" as const, text: JSON.stringify(result) }],
            isError: upstreamResult?.isError,
            _meta: {
              "x-gateway-attestation/v1": {
                auditId: auditRecord.id,
                attestation: auditRecord.attestation,
                timestamp: auditRecord.timestamp,
              },
            },
          };
        } catch (err) {
          if (err instanceof ToolCallError) {
            return {
              content: [{ type: "text" as const, text: err.message }],
              isError: true,
              _meta: {
                "x-gateway-attestation/v1": {
                  auditId: err.auditRecord.id,
                  attestation: err.auditRecord.attestation,
                  timestamp: err.auditRecord.timestamp,
                },
              },
            };
          }
          throw err;
        }
      },
    );
  }

  private extractPrincipal(meta?: Record<string, unknown>): string | undefined {
    if (this.resolvePrincipal) {
      return this.resolvePrincipal(meta);
    }
    return undefined;
  }

  private extractTraceContext(
    meta?: Record<string, unknown>,
  ): { traceparent?: string; tracestate?: string } | undefined {
    if (!meta) return undefined;
    const tc = meta.traceContext as { traceparent?: string; tracestate?: string } | undefined;
    return tc;
  }
}

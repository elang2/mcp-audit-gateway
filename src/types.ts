import { z } from "zod";

export const UpstreamConfigSchema = z.object({
  name: z.string(),
  namespace: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/),
  transport: z.discriminatedUnion("type", [
    z.object({
      type: z.literal("stdio"),
      command: z.string(),
      args: z.array(z.string()).optional(),
      env: z.record(z.string()).optional(),
    }),
    z.object({
      type: z.literal("streamable-http"),
      url: z.string().url(),
      headers: z.record(z.string()).optional(),
    }),
  ]),
  healthCheckIntervalMs: z.number().positive().optional(),
});

export const PolicyRuleSchema = z.object({
  effect: z.enum(["allow", "deny"]),
  principals: z.array(z.string()).optional(),
  tools: z.array(z.string()).optional(),
  namespaces: z.array(z.string()).optional(),
  rateLimit: z
    .object({
      maxPerMinute: z.number().positive().optional(),
      maxPerHour: z.number().positive().optional(),
    })
    .optional(),
});

export const AttestationConfigSchema = z.object({
  enabled: z.boolean().default(true),
  algorithm: z.enum(["ed25519", "hmac-sha256"]).default("ed25519"),
  keyPath: z.string().optional(),
  secret: z.string().optional(),
  includeParams: z.boolean().optional().default(false),
  includeResult: z.boolean().optional().default(false),
});

export const TelemetryConfigSchema = z.object({
  enabled: z.boolean().default(true),
  exporterEndpoint: z.string().url().optional(),
  serviceName: z.string().default("mcp-audit-gateway"),
  sampleRate: z.number().min(0).max(1).default(1.0),
});

export const CheckpointConfigSchema = z.object({
  enabled: z.boolean().default(false),
  intervalRecords: z.number().positive().default(100),
  intervalSeconds: z.number().positive().default(60),
  trigger: z.enum(["records", "time", "whichever_first"]).default("whichever_first"),
});

export const ToolIntegrityConfigSchema = z.object({
  enabled: z.boolean().default(false),
  action: z.enum(["record", "record_and_block"]).default("record"),
});

export const GatewayConfigSchema = z.object({
  name: z.string().default("mcp-audit-gateway"),
  version: z.string().default("0.1.0"),
  listen: z.object({
    transport: z.enum(["stdio", "streamable-http"]).default("streamable-http"),
    port: z.number().positive().default(3100),
    host: z.string().default("127.0.0.1"),
    principalHeader: z.string().optional(),
  }).default({}),
  upstreams: z.array(UpstreamConfigSchema).min(1),
  policy: z.object({
    defaultEffect: z.enum(["allow", "deny"]).default("allow"),
    rules: z.array(PolicyRuleSchema).default([]),
  }).default({}),
  attestation: AttestationConfigSchema.default({}),
  telemetry: TelemetryConfigSchema.default({}),
  auditLog: z.object({
    enabled: z.boolean().default(true),
    path: z.string().default("./audit.jsonl"),
    rotateAfterMb: z.number().positive().default(100),
  }).default({}),
  checkpoint: CheckpointConfigSchema.default({}),
  toolIntegrity: ToolIntegrityConfigSchema.default({}),
});

export type UpstreamConfig = z.infer<typeof UpstreamConfigSchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type AttestationConfig = z.infer<typeof AttestationConfigSchema>;
export type TelemetryConfig = z.infer<typeof TelemetryConfigSchema>;
export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

export interface UpstreamStatus {
  name: string;
  namespace: string;
  status: "healthy" | "degraded" | "unavailable" | "cooldown";
  toolCount: number;
  lastSuccessfulContact: string | null;
  degradedReason?: string;
  unavailableReason?: string;
}

export interface PartyAttribution {
  party: string;
  role: "witness" | "asserter";
  scope: string[];
}

export interface AiInvocationContext {
  turnId?: string;
  invocationReason?: string;
  model?: string;
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  method: string;
  toolName?: string;
  namespace?: string;
  upstream?: string;
  principal?: string;
  durationMs: number;
  success: boolean;
  errorCode?: number;
  decisionContextDigest?: string;
  extensionsDigest?: string;
  aiInvocation?: AiInvocationContext;
  parties?: PartyAttribution[];
  previousHash?: string;
  attestation?: string;
}

export interface CheckpointRecord {
  id: string;
  type: "checkpoint";
  timestamp: string;
  sequence: number;
  recordCount: number;
  previousHash: string;
  parties?: PartyAttribution[];
  attestation?: string;
}

export interface ChainBreakRecord {
  id: string;
  type: "chain_break";
  timestamp: string;
  reason: string;
  priorHead?: string;
  priorSequence?: number;
  priorRecordCount?: number;
  attestation?: string;
}

export interface ToolDriftRecord {
  id: string;
  type: "tool_drift";
  timestamp: string;
  toolName: string;
  namespace: string;
  previousDefinitionDigest: string;
  newDefinitionDigest: string;
  detectedAtRecord: number;
  previousHash: string;
  attestation?: string;
}

export type ChainRecord = AuditRecord | CheckpointRecord | ChainBreakRecord | ToolDriftRecord;

export function isCheckpoint(record: ChainRecord): record is CheckpointRecord {
  return "type" in record && (record as CheckpointRecord).type === "checkpoint";
}

export function isChainBreak(record: ChainRecord): record is ChainBreakRecord {
  return "type" in record && (record as ChainBreakRecord).type === "chain_break";
}

export function isToolDrift(record: ChainRecord): record is ToolDriftRecord {
  return "type" in record && (record as ToolDriftRecord).type === "tool_drift";
}

export interface ToolEntry {
  name: string;
  originalName: string;
  namespace: string;
  upstream: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
}

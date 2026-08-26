export { Gateway, ToolCallError } from "./proxy/gateway.js";
export { runWrapProxy } from "./wrap/proxy.js";
export { McpServerAdapter } from "./proxy/mcp-server-adapter.js";
export { UpstreamManager } from "./proxy/upstream-manager.js";
export { PolicyEngine, computeDecisionContextDigest, type DecisionContext } from "./policy/engine.js";
export { AuditLog } from "./attestation/audit-log.js";
export { createSigner, HmacSigner, Ed25519Signer } from "./attestation/signer.js";
export { ToolIntegrityMonitor } from "./attestation/tool-integrity.js";
export { verifyAuditLog, verifyChainLines, verifyChain } from "./attestation/verify.js";
export {
  projectByRole,
  projectionDigest,
  rolesInRecord,
  partiesForRole,
  scopeForRoleAndParty,
  type PartyRole,
  type WitnessProjection,
} from "./attestation/witness.js";
export { generateKeyPair } from "./attestation/keygen.js";
export { GatewayTracer } from "./telemetry/tracer.js";
export {
  GatewayConfigSchema,
  type GatewayConfig,
  type UpstreamConfig,
  type PolicyRule,
  type AttestationConfig,
  type TelemetryConfig,
  type AuditRecord,
  type ToolDriftRecord,
  type ToolEntry,
  type UpstreamStatus,
} from "./types.js";

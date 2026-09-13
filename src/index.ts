export { Gateway, ToolCallError } from "./proxy/gateway.js";
export { runWrapProxy } from "./wrap/proxy.js";
export { McpServerAdapter } from "./proxy/mcp-server-adapter.js";
export { UpstreamManager } from "./proxy/upstream-manager.js";
export {
  PolicyEngine,
  computeDecisionContextDigest,
  // v1 is the pre-stability digest, exported so a verifier can reproduce
  // records written before the canonical form landed.
  computeDecisionContextDigestV1,
  DECISION_CONTEXT_DOMAIN_TAG,
  type DecisionContext,
} from "./policy/engine.js";
// hashRecord is exported alongside canonicalizeRecord below so a consumer can
// compare their own digest against this implementation's, which is what the
// README's canonicalisation example demonstrates.
export { AuditLog, hashRecord } from "./attestation/audit-log.js";
export {
  createSigner,
  HmacSigner,
  Ed25519Signer,
  // Exported so consumers can check their own canonicalisation against this
  // implementation's byte output, which is what the README's "Verify your
  // canonicalization against ours" example documents. Previously the README
  // showed `import { canonicalize }`, a name this package has never exported.
  canonicalizeRecord,
} from "./attestation/signer.js";
export { ToolIntegrityMonitor } from "./attestation/tool-integrity.js";
export {
  verifyAuditLog,
  verifyChainLines,
  verifyChain,
  // Lets a verifier confirm which policy context a decision was made in,
  // instead of trusting the digest the gateway stamped on the record.
  verifyDecisionContextDigest,
  type PolicySnapshot,
  type DecisionContextCheck,
  type DecisionContextStatus,
  type DecisionContextSummary,
} from "./attestation/verify.js";
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

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Exact replica of canonicalizeRecord from src/attestation/signer.ts
function canonicalizeRecord(record) {
  const ordered = [
    ["id", record.id],
    ["timestamp", record.timestamp],
    ["method", record.method],
    ["toolName", record.toolName ?? null],
    ["namespace", record.namespace ?? null],
    ["upstream", record.upstream ?? null],
    ["principal", record.principal ?? null],
    ["durationMs", record.durationMs],
    ["success", record.success],
    ["errorCode", record.errorCode ?? null],
    ["previousHash", record.previousHash ?? null],
  ];
  return JSON.stringify(ordered);
}

// Exact replica of hashRecord from src/attestation/audit-log.ts
function hashRecord(record) {
  const json = JSON.stringify(record);
  return { hash: sha256Hex(json), json };
}

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

// --- Canonicalization test vectors ---

const vectorDefs = [
  {
    name: "genesis_all_fields",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440001",
      timestamp: "2026-08-21T12:00:00.000Z",
      method: "tools/call",
      toolName: "weather_lookup",
      namespace: "external-apis",
      upstream: "weather-server",
      principal: "user:alice@example.com",
      durationMs: 142,
      success: true,
      previousHash: "genesis",
    },
  },
  {
    name: "genesis_null_optionals",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440002",
      timestamp: "2026-08-21T12:00:01.000Z",
      method: "tools/list",
      durationMs: 3,
      success: true,
      previousHash: "genesis",
    },
  },
  {
    name: "error_with_code",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440003",
      timestamp: "2026-08-21T12:00:02.500Z",
      method: "tools/call",
      toolName: "database_query",
      namespace: "internal",
      upstream: "db-server",
      principal: "service:backend-agent",
      durationMs: 5021,
      success: false,
      errorCode: -32603,
      previousHash: "genesis",
    },
  },
  {
    name: "zero_duration",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440004",
      timestamp: "2026-08-21T12:00:03.000Z",
      method: "tools/call",
      toolName: "cache_get",
      namespace: "infra",
      upstream: "cache-server",
      durationMs: 0,
      success: true,
      previousHash: "genesis",
    },
  },
  {
    name: "invalid_params_error",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440005",
      timestamp: "2026-08-21T12:00:04.000Z",
      method: "tools/call",
      toolName: "send_email",
      namespace: "comms",
      upstream: "email-server",
      principal: "user:bob@example.com",
      durationMs: 12,
      success: false,
      errorCode: -32602,
      previousHash: "genesis",
    },
  },
  {
    name: "unicode_in_fields",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440006",
      timestamp: "2026-08-21T12:00:05.000Z",
      method: "tools/call",
      toolName: "天気検索",
      namespace: "external-apis",
      upstream: "weather-server-⚡",
      principal: "user:tanaka.太郎@example.jp",
      durationMs: 88,
      success: true,
      previousHash: "genesis",
    },
  },
  {
    name: "max_safe_integer_duration",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440007",
      timestamp: "2026-08-21T12:00:06.000Z",
      method: "tools/call",
      toolName: "long_running_task",
      namespace: "compute",
      upstream: "batch-server",
      principal: "service:scheduler",
      durationMs: 9007199254740991,
      success: true,
      previousHash: "genesis",
    },
  },
  {
    name: "empty_string_tool_name",
    record: {
      id: "550e8400-e29b-41d4-a716-446655440008",
      timestamp: "2026-08-21T12:00:07.000Z",
      method: "tools/call",
      toolName: "",
      namespace: "",
      upstream: "legacy-server",
      principal: "user:admin",
      durationMs: 1,
      success: true,
      previousHash: "genesis",
    },
  },
];

const canonicalizationVectors = vectorDefs.map(({ name, record }) => {
  const canonical = canonicalizeRecord(record);
  return {
    name,
    record,
    canonical,
    sha256_canonical: sha256Hex(canonical),
  };
});

// --- Chain vectors: 3 linked records ---

const chain1 = {
  id: "660e8400-e29b-41d4-a716-446655440001",
  timestamp: "2026-08-21T13:00:00.000Z",
  method: "tools/call",
  toolName: "search",
  namespace: "research",
  upstream: "search-server",
  principal: "user:carol@example.com",
  durationMs: 230,
  success: true,
  previousHash: "genesis",
  attestation: "abc123deadbeef",
};

const { hash: chain1_hash, json: chain1_json } = hashRecord(chain1);

const chain2 = {
  id: "660e8400-e29b-41d4-a716-446655440002",
  timestamp: "2026-08-21T13:00:01.500Z",
  method: "tools/call",
  toolName: "summarize",
  namespace: "research",
  upstream: "llm-server",
  principal: "user:carol@example.com",
  durationMs: 1840,
  success: true,
  previousHash: chain1_hash,
  attestation: "def456cafebabe",
};

const { hash: chain2_hash, json: chain2_json } = hashRecord(chain2);

const chain3 = {
  id: "660e8400-e29b-41d4-a716-446655440003",
  timestamp: "2026-08-21T13:00:05.000Z",
  method: "tools/call",
  toolName: "store_result",
  namespace: "research",
  upstream: "storage-server",
  principal: "user:carol@example.com",
  durationMs: 45,
  success: true,
  previousHash: chain2_hash,
  attestation: "789abcfeedface",
};

const { hash: chain3_hash, json: chain3_json } = hashRecord(chain3);

const chainVectors = {
  description:
    "Three linked records demonstrating hash chain verification. The chain hash covers the FULL record including the attestation field. This means the attestation (signature) is bound into the chain sequence.",
  chain_algorithm: "sha256(JSON.stringify(fullRecord))",
  chain_key_order: [
    "id",
    "timestamp",
    "method",
    "toolName",
    "namespace",
    "upstream",
    "principal",
    "durationMs",
    "success",
    "previousHash",
    "attestation",
  ],
  chain_key_order_note:
    "The chain hash uses JSON.stringify which preserves JavaScript insertion order. Verifiers in languages without ordered maps MUST serialize keys in this exact order to reproduce chain hashes. The canonical form (tuple-array) does NOT have this limitation.",
  genesis_seed: "genesis",
  records: [
    {
      record: chain1,
      full_record_json: chain1_json,
      record_hash: chain1_hash,
      canonical: canonicalizeRecord(chain1),
      sha256_canonical: sha256Hex(canonicalizeRecord(chain1)),
    },
    {
      record: chain2,
      full_record_json: chain2_json,
      record_hash: chain2_hash,
      canonical: canonicalizeRecord(chain2),
      sha256_canonical: sha256Hex(canonicalizeRecord(chain2)),
      previous_record_hash: chain1_hash,
    },
    {
      record: chain3,
      full_record_json: chain3_json,
      record_hash: chain3_hash,
      canonical: canonicalizeRecord(chain3),
      sha256_canonical: sha256Hex(canonicalizeRecord(chain3)),
      previous_record_hash: chain2_hash,
    },
  ],
};

// --- Dual-hash demonstration vector ---
// Same logical fields, different attestation → same canonical hash, different chain hash

const dualBase = {
  id: "770e8400-e29b-41d4-a716-446655440001",
  timestamp: "2026-08-21T14:00:00.000Z",
  method: "tools/call",
  toolName: "verify_identity",
  namespace: "auth",
  upstream: "identity-server",
  principal: "user:dave@example.com",
  durationMs: 55,
  success: true,
  previousHash: "genesis",
};

const dualA = { ...dualBase, attestation: "sig_aaa111" };
const dualB = { ...dualBase, attestation: "sig_bbb222" };

const dualHashDemo = {
  description:
    "Two records with identical auditable fields but different attestation values. They produce the SAME canonical hash (attestation is excluded from signing) but DIFFERENT chain hashes (attestation is included in chain). This demonstrates the dual-hash design.",
  record_a: {
    record: dualA,
    canonical: canonicalizeRecord(dualA),
    sha256_canonical: sha256Hex(canonicalizeRecord(dualA)),
    full_record_json: JSON.stringify(dualA),
    record_hash: sha256Hex(JSON.stringify(dualA)),
  },
  record_b: {
    record: dualB,
    canonical: canonicalizeRecord(dualB),
    sha256_canonical: sha256Hex(canonicalizeRecord(dualB)),
    full_record_json: JSON.stringify(dualB),
    record_hash: sha256Hex(JSON.stringify(dualB)),
  },
  assertions: {
    canonical_hashes_match:
      sha256Hex(canonicalizeRecord(dualA)) ===
      sha256Hex(canonicalizeRecord(dualB)),
    chain_hashes_differ:
      sha256Hex(JSON.stringify(dualA)) !== sha256Hex(JSON.stringify(dualB)),
  },
};

// --- Assemble output ---

const output = {
  format_version: "1.1.0",
  implementation: "mcp-audit-gateway",
  canonical_form: "tuple-array",
  description:
    "Conformance vectors for mcp-audit-gateway's tuple-array canonicalization and SHA-256 hash chain.",
  encoding: "utf-8",
  hash_algorithm: "sha256",
  hash_output: "hex-lowercase",
  null_rule:
    "Fields listed in field_order that are absent or undefined in the source record MUST be serialized as JSON null in the tuple-array canonical form.",
  signing_exclusions: ["attestation"],
  signing_note:
    "The attestation field is excluded from the canonical form used for signing. It cannot be included because the signature IS the attestation value (including it would be circular). The canonical form contains exactly the 11 fields listed in field_order.",
  chain_hash_note:
    "The chain hash (record_hash) uses JSON.stringify(fullRecord) which INCLUDES the attestation field. This binds the signature into the chain sequence, preventing attestation stripping without breaking the chain. The chain hash depends on JavaScript insertion order; verifiers must serialize keys in the order specified by chain.chain_key_order.",
  field_order: [
    "id",
    "timestamp",
    "method",
    "toolName",
    "namespace",
    "upstream",
    "principal",
    "durationMs",
    "success",
    "errorCode",
    "previousHash",
  ],
  canonicalization: canonicalizationVectors,
  chain: chainVectors,
  dual_hash_demo: dualHashDemo,
};

writeFileSync(
  join(__dirname, "canonicalization.json"),
  JSON.stringify(output, null, 2) + "\n",
);

console.log("Generated test/vectors/canonicalization.json");
console.log(`  ${canonicalizationVectors.length} canonicalization vectors`);
console.log(`  ${chainVectors.records.length} chain vectors`);
console.log(`  1 dual-hash demonstration`);

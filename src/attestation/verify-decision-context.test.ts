import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  verifyAuditLog,
  verifyDecisionContextDigest,
  type PolicySnapshot,
} from "./verify.js";
import { HmacSigner } from "./signer.js";
import {
  computeDecisionContextDigest,
  computeDecisionContextDigestV1,
  type DecisionContext,
} from "../policy/engine.js";
import { Gateway, ToolCallError } from "../proxy/gateway.js";
import type { AuditRecord, GatewayConfig, PolicyRule } from "../types.js";

const SECRET = "a".repeat(64);

const DENY_RULE: PolicyRule = {
  effect: "deny",
  principals: ["agent:blocked"],
  tools: ["test/dangerous_tool"],
};

const POLICY: PolicySnapshot = { defaultEffect: "allow", rules: [DENY_RULE] };

const gatewayConfig: GatewayConfig = {
  name: "test-gateway",
  version: "0.1.0",
  listen: { transport: "streamable-http", port: 3121, host: "127.0.0.1" },
  upstreams: [
    {
      name: "test-server",
      namespace: "test",
      transport: { type: "stdio", command: "echo", args: [] },
    },
  ],
  policy: POLICY,
  attestation: {
    enabled: true,
    algorithm: "hmac-sha256",
    secret: SECRET,
    includeParams: false,
    includeResult: false,
  },
  telemetry: { enabled: false, serviceName: "test", sampleRate: 0 },
  auditLog: { enabled: false, path: "/tmp/unused-audit.jsonl", rotateAfterMb: 10 },
  checkpoint: {
    enabled: false,
    intervalRecords: 100,
    intervalSeconds: 60,
    trigger: "whichever_first" as const,
  },
  toolIntegrity: { enabled: false, action: "record" as const },
};

/**
 * The only source of a record whose digest was produced by the real code path.
 * Building one by hand would test the test's idea of a decision context rather
 * than the gateway's.
 */
async function deniedRecord(gateway: Gateway, principal: string): Promise<AuditRecord> {
  try {
    await gateway.handleToolsCall("test/dangerous_tool", {}, principal);
  } catch (err) {
    return (err as ToolCallError).auditRecord;
  }
  throw new Error(`expected test/dangerous_tool to be denied for ${principal}`);
}

// The digest is only useful to a verifier if it is a function of the logical
// context and nothing else. v1 hashed JSON.stringify of an array holding the
// raw rule object, so it also depended on the rule's key insertion order --
// which is why verify.ts never recomputed it. These are the regression guards
// for the property that makes recomputation possible at all.
describe("computeDecisionContextDigest stability", () => {
  const base: Omit<DecisionContext, "matchedRule"> = {
    principal: "agent:blocked",
    toolName: "test/dangerous_tool",
    toolNamespace: "test",
    toolUpstream: "test-server",
    effect: "deny",
  };
  const digest = (matchedRule: PolicyRule | null): string =>
    computeDecisionContextDigest({ ...base, matchedRule });

  it("is unchanged when the rule's keys are written in a different order", () => {
    const a = { effect: "deny", principals: ["agent:blocked"], tools: ["test/dangerous_tool"] };
    const b = { tools: ["test/dangerous_tool"], principals: ["agent:blocked"], effect: "deny" };
    const c = { principals: ["agent:blocked"], effect: "deny", tools: ["test/dangerous_tool"] };

    expect(digest(a as PolicyRule)).toBe(digest(b as PolicyRule));
    expect(digest(a as PolicyRule)).toBe(digest(c as PolicyRule));

    // And v1 is the reason this test exists: it disagrees on the same inputs.
    const v1 = (r: PolicyRule): string => computeDecisionContextDigestV1({ ...base, matchedRule: r });
    expect(v1(a as PolicyRule)).not.toBe(v1(b as PolicyRule));
  });

  it("is unchanged whether an unused optional is absent, undefined or null", () => {
    const absent = { effect: "deny", tools: ["test/dangerous_tool"] };
    const undef = { effect: "deny", tools: ["test/dangerous_tool"], rateLimit: undefined };
    const nulled = { effect: "deny", tools: ["test/dangerous_tool"], rateLimit: null };

    expect(digest(undef as PolicyRule)).toBe(digest(absent as PolicyRule));
    // The engine reads every optional as falsy-or-present, so an explicit null
    // and an omitted key describe the same rule and must digest alike.
    expect(digest(nulled as unknown as PolicyRule)).toBe(digest(absent as PolicyRule));
  });

  it("still separates contexts that actually differ", () => {
    const rule = { effect: "deny", tools: ["test/dangerous_tool"] } as PolicyRule;
    const d = digest(rule);

    expect(digest(null)).not.toBe(d);
    expect(computeDecisionContextDigest({ ...base, matchedRule: rule, effect: "allow" })).not.toBe(d);
    expect(computeDecisionContextDigest({ ...base, matchedRule: rule, principal: null })).not.toBe(d);
    expect(
      computeDecisionContextDigest({ ...base, matchedRule: rule, toolNamespace: "other" }),
    ).not.toBe(d);
    // A rule that denies a different tool is a different context.
    expect(digest({ effect: "deny", tools: ["test/other"] } as PolicyRule)).not.toBe(d);
  });

  it("is domain-separated from the v1 digest of the same context", () => {
    const rule = { effect: "deny", tools: ["test/dangerous_tool"] } as PolicyRule;
    expect(digest(rule)).not.toBe(computeDecisionContextDigestV1({ ...base, matchedRule: rule }));
  });
});

describe("verifyDecisionContextDigest", () => {
  let gateway: Gateway;

  beforeEach(async () => {
    gateway = new Gateway(gatewayConfig);
    await gateway.init();
    gateway.registerUpstreamTools("test-server", "test", [
      { name: "dangerous_tool", description: "A dangerous tool" },
    ]);
  });

  afterEach(async () => {
    await gateway.shutdown();
  });

  it("reproduces the digest a real gateway record carries", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");

    const check = verifyDecisionContextDigest(record, POLICY);

    expect(check.status).toBe("match");
    expect(check.digestVersion).toBe("v2");
    expect(check.effect).toBe("deny");
    expect(check.matchedRuleIndex).toBe(0);
    expect(check.storedDigest).toBe(record.decisionContextDigest);
    expect(check.recomputedDigest).toBe(record.decisionContextDigest);
    expect(check.rateLimitInferred).toBeUndefined();
  });

  it("reproduces it from a policy whose rule keys are in a different order", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");

    // Same policy, re-spelled. This is the case a verifier actually hits: it
    // loads the policy from its own copy of the config, and key order is not
    // preserved across a round trip through most config tooling.
    const reordered: PolicySnapshot = {
      defaultEffect: "allow",
      rules: [
        {
          tools: ["test/dangerous_tool"],
          effect: "deny",
          principals: ["agent:blocked"],
        } as PolicyRule,
      ],
    };

    expect(verifyDecisionContextDigest(record, reordered).status).toBe("match");
  });

  it("reproduces it for a rule written against the bare upstream tool name", async () => {
    // ruleMatches tests the qualified name AND tool.originalName, so a policy
    // may legitimately name the tool without its namespace. The record only
    // stores the qualified name, so the verifier has to derive originalName by
    // stripping the namespace prefix -- if it does not, this rule never matches
    // and the recomputed context is the default-effect one instead.
    const bareRule: PolicyRule = {
      effect: "deny",
      principals: ["agent:blocked"],
      tools: ["dangerous_tool"],
    };
    const barePolicy: PolicySnapshot = { defaultEffect: "allow", rules: [bareRule] };

    const bareGateway = new Gateway({ ...gatewayConfig, policy: barePolicy });
    await bareGateway.init();
    bareGateway.registerUpstreamTools("test-server", "test", [
      { name: "dangerous_tool", description: "A dangerous tool" },
    ]);
    const record = await deniedRecord(bareGateway, "agent:blocked");
    await bareGateway.shutdown();

    const check = verifyDecisionContextDigest(record, barePolicy);
    expect(check.status).toBe("match");
    expect(check.matchedRuleIndex).toBe(0);
  });

  it("reports mismatch when the stored digest was altered", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");
    const tampered: AuditRecord = { ...record, decisionContextDigest: "f".repeat(64) };

    const check = verifyDecisionContextDigest(tampered, POLICY);

    expect(check.status).toBe("mismatch");
    expect(check.recomputedDigest).toBe(record.decisionContextDigest);
    expect(check.reason).toMatch(/does not reproduce/);
  });

  it("reports mismatch when the record's principal was altered", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");
    // Rewriting who was evaluated while keeping the digest is exactly the edit
    // the digest exists to catch.
    const tampered: AuditRecord = { ...record, principal: "agent:innocent" };

    expect(verifyDecisionContextDigest(tampered, POLICY).status).toBe("mismatch");
  });

  it("reports mismatch when the record's tool identity was altered", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");

    expect(
      verifyDecisionContextDigest({ ...record, namespace: "other" }, POLICY).status,
    ).toBe("mismatch");
  });

  it("reports mismatch when the policy has drifted from the one in force", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");
    const drifted: PolicySnapshot = {
      defaultEffect: "allow",
      rules: [{ effect: "deny", principals: ["agent:blocked"], tools: ["test/*"] }],
    };

    // Same verdict for this call, different rule, so a different context.
    const check = verifyDecisionContextDigest(record, drifted);
    expect(check.status).toBe("mismatch");
    expect(check.effect).toBe("deny");
  });

  it("accepts a record written under the v1 digest and says which version matched", () => {
    const ctx: DecisionContext = {
      principal: "agent:blocked",
      toolName: "test/dangerous_tool",
      toolNamespace: "test",
      toolUpstream: "test-server",
      matchedRule: DENY_RULE,
      effect: "deny",
    };
    const legacy: AuditRecord = {
      id: "legacy-1",
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 1,
      success: false,
      toolName: ctx.toolName,
      namespace: ctx.toolNamespace,
      upstream: ctx.toolUpstream,
      principal: ctx.principal!,
      decisionContextDigest: computeDecisionContextDigestV1(ctx),
    };

    const check = verifyDecisionContextDigest(legacy, POLICY);
    expect(check.status).toBe("match");
    expect(check.digestVersion).toBe("v1");
  });

  it("admits a rate-limited deny it cannot derive, and flags that it inferred it", () => {
    // A rate-limit deny depends on the gateway's counters, which are runtime
    // state no verifier holds. The policy alone yields allow.
    const rule: PolicyRule = {
      effect: "allow",
      tools: ["test/metered_tool"],
      rateLimit: { maxPerMinute: 1 },
    };
    const policy: PolicySnapshot = { defaultEffect: "deny", rules: [rule] };
    const ctx: DecisionContext = {
      principal: "agent:busy",
      toolName: "test/metered_tool",
      toolNamespace: "test",
      toolUpstream: "test-server",
      matchedRule: rule,
      effect: "deny",
    };
    const record: AuditRecord = {
      id: "rl-1",
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 1,
      success: false,
      toolName: ctx.toolName,
      namespace: ctx.toolNamespace,
      upstream: ctx.toolUpstream,
      principal: ctx.principal!,
      decisionContextDigest: computeDecisionContextDigest(ctx),
    };

    const check = verifyDecisionContextDigest(record, policy);
    expect(check.status).toBe("match");
    expect(check.effect).toBe("deny");
    expect(check.rateLimitInferred).toBe(true);

    // The admission is narrow: drop the rateLimit and the same flip is refused.
    const noLimit: PolicySnapshot = {
      defaultEffect: "deny",
      rules: [{ effect: "allow", tools: ["test/metered_tool"] }],
    };
    expect(verifyDecisionContextDigest(record, noLimit).status).toBe("mismatch");
  });

  it("refuses an effect flip the policy cannot explain, rule held identical", () => {
    // Isolates the effect gate. The matched rule here is byte-identical to the
    // one the digest was computed over -- only the effect differs, and nothing
    // in the policy can turn this allow into a deny. Without the rateLimit
    // precondition on the opposite-effect candidate, a record could claim any
    // verdict it liked over a real rule and still verify.
    const rule: PolicyRule = { effect: "allow", tools: ["test/plain_tool"] };
    const policy: PolicySnapshot = { defaultEffect: "deny", rules: [rule] };
    const record: AuditRecord = {
      id: "flip-1",
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 1,
      success: false,
      toolName: "test/plain_tool",
      namespace: "test",
      upstream: "test-server",
      principal: "agent:any",
      decisionContextDigest: computeDecisionContextDigest({
        principal: "agent:any",
        toolName: "test/plain_tool",
        toolNamespace: "test",
        toolUpstream: "test-server",
        matchedRule: rule,
        effect: "deny",
      }),
    };

    const check = verifyDecisionContextDigest(record, policy);
    expect(check.status).toBe("mismatch");
    expect(check.effect).toBe("allow");

    // Sanity: the identical record with the derivable effect does verify, so
    // the mismatch above is the effect gate and not a broken reconstruction.
    const honest: AuditRecord = {
      ...record,
      decisionContextDigest: computeDecisionContextDigest({
        principal: "agent:any",
        toolName: "test/plain_tool",
        toolNamespace: "test",
        toolUpstream: "test-server",
        matchedRule: rule,
        effect: "allow",
      }),
    };
    expect(verifyDecisionContextDigest(honest, policy).status).toBe("match");
  });

  it("returns absent when the record carries no digest", () => {
    const record: AuditRecord = {
      id: "no-digest",
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 1,
      success: true,
    };
    const check = verifyDecisionContextDigest(record, POLICY);
    expect(check.status).toBe("absent");
    expect(check.recomputedDigest).toBeUndefined();
  });

  it("returns unverifiable, not mismatch, when a context input is missing", async () => {
    const record = await deniedRecord(gateway, "agent:blocked");
    const stripped = { ...record };
    delete stripped.namespace;

    const check = verifyDecisionContextDigest(stripped, POLICY);
    // A gap in the record is not evidence the record is wrong.
    expect(check.status).toBe("unverifiable");
    expect(check.reason).toMatch(/namespace/);
    expect(check.storedDigest).toBe(record.decisionContextDigest);
  });

  it("does not consume rate-limit budget on the caller's engine", () => {
    // verifyDecisionContextDigest runs evaluate() on a throwaway engine. If it
    // shared state, checking the same record twice would trip a 1/minute limit
    // and the second check would resolve differently from the first.
    const rule: PolicyRule = {
      effect: "allow",
      tools: ["test/metered_tool"],
      rateLimit: { maxPerMinute: 1 },
    };
    const policy: PolicySnapshot = { defaultEffect: "deny", rules: [rule] };
    const record: AuditRecord = {
      id: "rl-2",
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 1,
      success: true,
      toolName: "test/metered_tool",
      namespace: "test",
      upstream: "test-server",
      principal: "agent:busy",
      decisionContextDigest: computeDecisionContextDigest({
        principal: "agent:busy",
        toolName: "test/metered_tool",
        toolNamespace: "test",
        toolUpstream: "test-server",
        matchedRule: rule,
        effect: "allow",
      }),
    };

    for (let i = 0; i < 5; i++) {
      const check = verifyDecisionContextDigest(record, policy);
      expect(check.status).toBe("match");
      expect(check.effect).toBe("allow");
      expect(check.rateLimitInferred).toBeUndefined();
    }
  });
});

describe("verifyAuditLog with a policy", () => {
  let dir: string;
  let logPath: string;
  const signer = new HmacSigner(SECRET);

  const ctx: DecisionContext = {
    principal: "agent:blocked",
    toolName: "test/dangerous_tool",
    toolNamespace: "test",
    toolUpstream: "test-server",
    matchedRule: DENY_RULE,
    effect: "deny",
  };

  function baseRecord(id: string): AuditRecord {
    return {
      id,
      timestamp: "2026-08-16T14:32:01.000Z",
      method: "tools/call",
      durationMs: 3,
      success: false,
      toolName: ctx.toolName,
      namespace: ctx.toolNamespace,
      upstream: ctx.toolUpstream,
      principal: ctx.principal!,
      decisionContextDigest: computeDecisionContextDigest(ctx),
    };
  }

  async function writeLog(records: AuditRecord[]): Promise<void> {
    const lines: string[] = [];
    for (const record of records) {
      const attestation = await signer.sign(record);
      lines.push(JSON.stringify({ ...record, attestation }));
    }
    await writeFile(logPath, lines.join("\n") + "\n", "utf8");
  }

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "mag-dc-"));
    logPath = join(dir, "audit.jsonl");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("does not check the digest unless a policy is supplied", async () => {
    await writeLog([baseRecord("r1")]);

    const result = await verifyAuditLog(logPath, signer);
    expect(result.decisionContext).toBeUndefined();
    expect(result.valid).toBe(1);
  });

  it("summarises matches when every record was written under the policy", async () => {
    await writeLog([baseRecord("r1"), baseRecord("r2")]);

    const result = await verifyAuditLog(logPath, signer, { policy: POLICY });

    expect(result.decisionContext).toEqual({
      checked: 2,
      matched: 2,
      mismatched: 0,
      unverifiable: 0,
      absent: 0,
    });
    expect(result.valid).toBe(2);
    expect(result.invalid).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it("demotes a signature-valid record whose digest does not reproduce", async () => {
    // Sign a record that claims a digest belonging to a different context. The
    // signature is genuine, so only the policy recomputation can catch this.
    const forged: AuditRecord = {
      ...baseRecord("r2"),
      decisionContextDigest: computeDecisionContextDigest({ ...ctx, matchedRule: null }),
    };
    await writeLog([baseRecord("r1"), forged]);

    const result = await verifyAuditLog(logPath, signer, { policy: POLICY });

    expect(result.total).toBe(2);
    expect(result.valid).toBe(1);
    expect(result.invalid).toBe(1);
    expect(result.decisionContext!.mismatched).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].id).toBe("r2");

    // Without the policy the forgery is invisible, which is the gap this closes.
    const blind = await verifyAuditLog(logPath, signer);
    expect(blind.valid).toBe(2);
    expect(blind.invalid).toBe(0);
  });

  it("counts records with no digest as absent rather than checked", async () => {
    const noDigest = { ...baseRecord("r2") };
    delete noDigest.decisionContextDigest;
    await writeLog([baseRecord("r1"), noDigest]);

    const result = await verifyAuditLog(logPath, signer, { policy: POLICY });

    expect(result.decisionContext).toMatchObject({ checked: 1, matched: 1, absent: 1 });
    expect(result.valid).toBe(2);
  });

  it("does not demote a record whose digest is merely unverifiable", async () => {
    const stripped = { ...baseRecord("r2") };
    delete stripped.upstream;
    await writeLog([stripped]);

    const result = await verifyAuditLog(logPath, signer, { policy: POLICY });

    expect(result.decisionContext!.unverifiable).toBe(1);
    expect(result.valid).toBe(1);
    expect(result.invalid).toBe(0);
    expect(result.errors).toHaveLength(1);
  });

  it("counts a record failing both chain and digest checks only once", async () => {
    // Chain mode wants previousHash; this record has none and also carries a
    // digest from a different context. Two failures, one record: valid+invalid
    // must still sum to total.
    const doubleFail: AuditRecord = {
      ...baseRecord("r1"),
      decisionContextDigest: computeDecisionContextDigest({ ...ctx, matchedRule: null }),
    };
    await writeLog([doubleFail]);

    const result = await verifyAuditLog(logPath, signer, {
      policy: POLICY,
      verifyChain: true,
    });

    expect(result.total).toBe(1);
    expect(result.valid).toBe(0);
    expect(result.invalid).toBe(1);
    expect(result.valid + result.invalid).toBe(result.total);
    expect(result.errors).toHaveLength(2);
  });
});

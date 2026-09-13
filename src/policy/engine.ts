import { createHash } from "node:crypto";
import { canonicalizeValue } from "../attestation/signer.js";
import type { PolicyRule, ToolEntry } from "../types.js";

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  rateLimit?: { maxPerMinute?: number; maxPerHour?: number };
}

export interface DecisionContext {
  principal: string | null;
  toolName: string;
  toolNamespace: string;
  toolUpstream: string;
  matchedRule: PolicyRule | null;
  effect: "allow" | "deny";
}

/**
 * Domain tag for the decision-context digest, in the same style as
 * PROJECTION_DOMAIN_TAG in attestation/witness.ts: the hashed bytes begin with
 * the tag, so a decision-context digest cannot collide with a record hash or a
 * witness-projection digest even on identical inner content.
 *
 * v2 exists because v1 was not reproducible. See computeDecisionContextDigestV1.
 */
export const DECISION_CONTEXT_DOMAIN_TAG = "DecisionContext/v2";

/**
 * The original digest, preserved verbatim so records written before v2 still
 * verify. Do not use for new records.
 *
 * It hashed `JSON.stringify` of an array holding the raw `matchedRule` object,
 * and `JSON.stringify` emits object keys in insertion order. Two semantically
 * identical rules therefore produced different digests when their keys were
 * written in a different order, and a rule carrying an explicit `null` optional
 * differed from the same rule with the key absent. Verified empirically: the
 * rule `{effect, principals, tools}` and the same rule spelled
 * `{tools, principals, effect}` hash differently.
 *
 * That is why nothing on the verify side ever recomputed this value -- given a
 * record and the policy, the digest could not be reliably reproduced, because
 * reproduction depended on the key order of an in-memory object that no longer
 * existed. v2 fixes the property rather than the symptom.
 */
export function computeDecisionContextDigestV1(ctx: DecisionContext): string {
  const ordered: [string, unknown][] = [
    ["principal", ctx.principal],
    ["toolName", ctx.toolName],
    ["toolNamespace", ctx.toolNamespace],
    ["toolUpstream", ctx.toolUpstream],
    ["matchedRule", ctx.matchedRule],
    ["effect", ctx.effect],
  ];
  const canonical = JSON.stringify(ordered);
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Drops object members whose value is `null` or `undefined`, recursively.
 * Array elements are left alone, including null elements.
 *
 * canonicalizeValue already drops `undefined` members, but it keeps explicit
 * `null` ones. For a PolicyRule that distinction carries no meaning: every
 * optional field is read as falsy-or-present (`rule.principals && length > 0`,
 * `rule.rateLimit`, `limit.maxPerMinute != null`), so a rule spelled
 * `{effect, rateLimit: null}` behaves identically to `{effect}`. Folding the
 * two together before hashing means a policy file that writes its optionals as
 * explicit nulls digests the same as one that omits them.
 *
 * Applied to the whole ordered tuple list rather than just the rule: the tuples
 * are arrays, so `["principal", null]` keeps its null and an anonymous
 * principal stays distinguishable from a named one.
 */
function dropNullMembers(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(dropNullMembers);
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === null || v === undefined) continue;
    out[k] = dropNullMembers(v);
  }
  return out;
}

/**
 * Digest of the policy context a decision was made in, stable across any
 * re-serialisation of the same logical context.
 *
 * Two normalisations run before hashing. dropNullMembers folds explicit-null
 * optionals together with absent ones, and canonicalizeValue sorts object keys
 * and type-tags containers, so neither key order nor optional-field spelling
 * can change the result. That is what makes the digest recomputable by a
 * verifier holding only the record and the policy -- see
 * verifyDecisionContextDigest in attestation/verify.ts.
 */
export function computeDecisionContextDigest(ctx: DecisionContext): string {
  const ordered: [string, unknown][] = [
    ["principal", ctx.principal],
    ["toolName", ctx.toolName],
    ["toolNamespace", ctx.toolNamespace],
    ["toolUpstream", ctx.toolUpstream],
    ["matchedRule", ctx.matchedRule],
    ["effect", ctx.effect],
  ];
  const canonical = JSON.stringify([
    DECISION_CONTEXT_DOMAIN_TAG,
    canonicalizeValue(dropNullMembers(ordered)),
  ]);
  return createHash("sha256").update(canonical).digest("hex");
}

interface RateLimitState {
  minuteCounts: Map<string, { count: number; resetAt: number }>;
  hourCounts: Map<string, { count: number; resetAt: number }>;
}

export class PolicyEngine {
  private rateLimitState: RateLimitState = {
    minuteCounts: new Map(),
    hourCounts: new Map(),
  };

  constructor(
    private defaultEffect: "allow" | "deny",
    private rules: PolicyRule[],
  ) {}

  evaluate(principal: string | undefined, tool: ToolEntry): PolicyDecision & { decisionContext: DecisionContext } {
    let matchedRule: PolicyRule | null = null;

    for (const rule of this.rules) {
      if (this.ruleMatches(rule, principal, tool)) {
        matchedRule = rule;
        break;
      }
    }

    const buildContext = (effect: "allow" | "deny"): DecisionContext => ({
      principal: principal ?? null,
      toolName: tool.name,
      toolNamespace: tool.namespace,
      toolUpstream: tool.upstream,
      matchedRule,
      effect,
    });

    if (!matchedRule) {
      const allowed = this.defaultEffect === "allow";
      return { allowed, decisionContext: buildContext(allowed ? "allow" : "deny") };
    }

    if (matchedRule.effect === "deny") {
      return { allowed: false, reason: "denied by policy rule", decisionContext: buildContext("deny") };
    }

    if (matchedRule.rateLimit) {
      const key = `${principal ?? "anonymous"}:${tool.name}`;
      const rateLimited = this.checkRateLimit(key, matchedRule.rateLimit);
      if (rateLimited) {
        return { allowed: false, reason: "rate limit exceeded", rateLimit: matchedRule.rateLimit, decisionContext: buildContext("deny") };
      }
    }

    return { allowed: true, rateLimit: matchedRule.rateLimit, decisionContext: buildContext("allow") };
  }

  filterTools(principal: string | undefined, tools: ToolEntry[]): ToolEntry[] {
    return tools.filter((tool) => this.evaluate(principal, tool).allowed);
  }

  recordInvocation(principal: string | undefined, tool: ToolEntry): void {
    const key = `${principal ?? "anonymous"}:${tool.name}`;
    this.incrementCounter(key);
  }

  private ruleMatches(
    rule: PolicyRule,
    principal: string | undefined,
    tool: ToolEntry,
  ): boolean {
    if (rule.principals && rule.principals.length > 0) {
      if (!principal || !this.matchesPattern(principal, rule.principals)) {
        return false;
      }
    }

    if (rule.namespaces && rule.namespaces.length > 0) {
      if (!rule.namespaces.includes(tool.namespace)) {
        return false;
      }
    }

    if (rule.tools && rule.tools.length > 0) {
      if (!this.matchesPattern(tool.name, rule.tools) &&
          !this.matchesPattern(tool.originalName, rule.tools)) {
        return false;
      }
    }

    return true;
  }

  private matchesPattern(value: string, patterns: string[]): boolean {
    return patterns.some((pattern) => this.globMatch(pattern, value));
  }

  private globMatch(pattern: string, value: string): boolean {
    if (!pattern.includes("*")) return pattern === value;

    const parts = pattern.split("*");
    let pos = 0;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part === "") continue;

      if (i === 0) {
        if (!value.startsWith(part)) return false;
        pos = part.length;
      } else if (i === parts.length - 1) {
        if (value.length - pos < part.length) return false;
        if (!value.endsWith(part)) return false;
        const suffixStart = value.length - part.length;
        if (suffixStart < pos) return false;
      } else {
        const idx = value.indexOf(part, pos);
        if (idx === -1) return false;
        pos = idx + part.length;
      }
    }

    return true;
  }

  private checkRateLimit(
    key: string,
    limit: { maxPerMinute?: number; maxPerHour?: number },
  ): boolean {
    const now = Date.now();

    if (limit.maxPerMinute != null) {
      const entry = this.rateLimitState.minuteCounts.get(key);
      if (entry && entry.resetAt > now && entry.count >= limit.maxPerMinute) {
        return true;
      }
    }

    if (limit.maxPerHour != null) {
      const entry = this.rateLimitState.hourCounts.get(key);
      if (entry && entry.resetAt > now && entry.count >= limit.maxPerHour) {
        return true;
      }
    }

    return false;
  }

  private incrementCounter(key: string): void {
    const now = Date.now();

    const minute = this.rateLimitState.minuteCounts.get(key);
    if (!minute || minute.resetAt <= now) {
      this.rateLimitState.minuteCounts.set(key, { count: 1, resetAt: now + 60_000 });
    } else {
      minute.count++;
    }

    const hour = this.rateLimitState.hourCounts.get(key);
    if (!hour || hour.resetAt <= now) {
      this.rateLimitState.hourCounts.set(key, { count: 1, resetAt: now + 3_600_000 });
    } else {
      hour.count++;
    }
  }
}

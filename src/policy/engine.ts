import type { PolicyRule, ToolEntry } from "../types.js";

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  rateLimit?: { maxPerMinute?: number; maxPerHour?: number };
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

  evaluate(principal: string | undefined, tool: ToolEntry): PolicyDecision {
    let matchedRule: PolicyRule | null = null;

    for (const rule of this.rules) {
      if (this.ruleMatches(rule, principal, tool)) {
        matchedRule = rule;
        break;
      }
    }

    if (!matchedRule) {
      return { allowed: this.defaultEffect === "allow" };
    }

    if (matchedRule.effect === "deny") {
      return { allowed: false, reason: "denied by policy rule" };
    }

    if (matchedRule.rateLimit) {
      const key = `${principal ?? "anonymous"}:${tool.name}`;
      const rateLimited = this.checkRateLimit(key, matchedRule.rateLimit);
      if (rateLimited) {
        return { allowed: false, reason: "rate limit exceeded", rateLimit: matchedRule.rateLimit };
      }
    }

    return { allowed: true, rateLimit: matchedRule.rateLimit };
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

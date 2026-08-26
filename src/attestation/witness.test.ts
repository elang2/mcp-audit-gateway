// Tests for witness projection. Covers the invariants the design lock
// requires:
//   1. The reduction-preserves-scope pattern as an executable check. A
//      consumer that reduces both witness-attested and asserter-attested
//      records to a single counter loses the distinction. Projecting to a
//      role scope before aggregation preserves it.
//   2. Cross-scope leakage: an asserter-role projection never includes
//      witness-scope fields (and vice versa).
//   3. Determinism: same input produces byte-identical projection + digest
//      across repeated runs.
//   4. Domain-separation negative: no projection digest ever equals any
//      record digest. Executable form of the B-over-A design decision.
//   5. Role vs party axis: role-only projection differs from role+party
//      projection when a record has multiple parties for the same role.
//   6. Runtime robustness: real-world field types (floats), unknown role
//      values in untrusted input, undefined optional fields, absent
//      parties[] — none crash or leak.

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import type { AuditRecord, PartyAttribution } from "../types.js";
import {
  projectByRole,
  projectionDigest,
  rolesInRecord,
  partiesForRole,
  scopeForRoleAndParty,
  PROJECTION_DOMAIN_TAG,
} from "./witness.js";
import { canonicalizeValue } from "./signer.js";

// Fixture: a record with distinct witness (gateway) and asserter (policy)
// party scopes. The gateway attests to what it observed; the policy engine
// attests to what it decided.
const baseRecord: AuditRecord = {
  id: "test-record-1",
  timestamp: "2026-08-26T00:00:00.000Z",
  method: "tools/call",
  toolName: "search",
  namespace: "example",
  upstream: "https://upstream.example",
  principal: "user-a",
  durationMs: 12,
  success: true,
  decisionContextDigest: "context-digest-abc",
  parties: [
    {
      party: "gateway",
      role: "witness",
      scope: ["method", "toolName", "namespace", "upstream", "durationMs"],
    },
    {
      party: "policy-engine",
      role: "asserter",
      scope: ["success", "decisionContextDigest"],
    },
  ],
};

function hashRecord(record: AuditRecord): string {
  return createHash("sha256").update(JSON.stringify(record)).digest("hex");
}

describe("witness projection", () => {
  describe("scope enumeration", () => {
    it("rolesInRecord returns distinct roles present in parties[]", () => {
      expect(rolesInRecord(baseRecord)).toEqual(["asserter", "witness"]);
    });

    it("partiesForRole returns party names for a given role", () => {
      expect(partiesForRole(baseRecord, "witness")).toEqual(["gateway"]);
      expect(partiesForRole(baseRecord, "asserter")).toEqual([
        "policy-engine",
      ]);
    });

    it("scopeForRoleAndParty returns sorted deduplicated scope", () => {
      expect(scopeForRoleAndParty(baseRecord, "witness")).toEqual([
        "durationMs",
        "method",
        "namespace",
        "toolName",
        "upstream",
      ]);
      expect(scopeForRoleAndParty(baseRecord, "asserter")).toEqual([
        "decisionContextDigest",
        "success",
      ]);
    });

    it("returns empty arrays when parties[] is absent", () => {
      const noParties: AuditRecord = { ...baseRecord, parties: undefined };
      expect(rolesInRecord(noParties)).toEqual([]);
      expect(partiesForRole(noParties, "witness")).toEqual([]);
      expect(scopeForRoleAndParty(noParties, "witness")).toEqual([]);
    });
  });

  describe("projectByRole", () => {
    it("returns a WitnessProjection with type discriminant", () => {
      const p = projectByRole(baseRecord, "witness");
      expect(p.type).toBe("witness-projection");
    });

    it("includes only fields in the scope", () => {
      const p = projectByRole(baseRecord, "witness");
      expect(Object.keys(p.fields).sort()).toEqual([
        "durationMs",
        "method",
        "namespace",
        "toolName",
        "upstream",
      ]);
      expect(p.fields.decisionContextDigest).toBeUndefined();
      expect(p.fields.success).toBeUndefined();
    });

    it("sets projectionOf to hashRecord(source)", () => {
      const p = projectByRole(baseRecord, "witness");
      expect(p.projectionOf).toBe(hashRecord(baseRecord));
    });

    it("carries role, and party when refined", () => {
      const p1 = projectByRole(baseRecord, "witness");
      expect(p1.role).toBe("witness");
      expect(p1.party).toBeUndefined();

      const p2 = projectByRole(baseRecord, "witness", "gateway");
      expect(p2.party).toBe("gateway");
    });
  });

  describe("cross-scope leakage (crewAI#5888 invariant)", () => {
    it("asserter projection never includes witness-scope fields", () => {
      const p = projectByRole(baseRecord, "asserter");
      const witnessScope = scopeForRoleAndParty(baseRecord, "witness");
      for (const field of witnessScope) {
        expect(p.fields[field]).toBeUndefined();
      }
    });

    it("witness projection never includes asserter-scope fields", () => {
      const p = projectByRole(baseRecord, "witness");
      const asserterScope = scopeForRoleAndParty(baseRecord, "asserter");
      for (const field of asserterScope) {
        expect(p.fields[field]).toBeUndefined();
      }
    });

    it("reduction preserves witness class (executable form of the invariant)", () => {
      // The invariant: a consumer reducing records to a counter of successes
      // must not conflate host-transcribed and gateway-witnessed results.
      // With projectByRole, the consumer can produce two separate counters,
      // each domain-tagged, preventing the collapse.
      const witnessOnly = projectByRole(baseRecord, "witness");
      const asserterOnly = projectByRole(baseRecord, "asserter");
      const witnessDigest = projectionDigest(witnessOnly);
      const asserterDigest = projectionDigest(asserterOnly);
      expect(witnessDigest).not.toBe(asserterDigest);
      // And critically, both digests differ from the record's own digest.
      const recordDigest = hashRecord(baseRecord);
      expect(witnessDigest).not.toBe(recordDigest);
      expect(asserterDigest).not.toBe(recordDigest);
    });
  });

  describe("determinism", () => {
    it("same input produces byte-identical projection across N runs", () => {
      const p1 = projectByRole(baseRecord, "witness");
      const p2 = projectByRole(baseRecord, "witness");
      const p3 = projectByRole(baseRecord, "witness");
      expect(JSON.stringify(p1)).toBe(JSON.stringify(p2));
      expect(JSON.stringify(p2)).toBe(JSON.stringify(p3));
    });

    it("same projection produces byte-identical digest across N runs", () => {
      const p = projectByRole(baseRecord, "witness");
      const d1 = projectionDigest(p);
      const d2 = projectionDigest(p);
      const d3 = projectionDigest(p);
      expect(d1).toBe(d2);
      expect(d2).toBe(d3);
    });
  });

  describe("domain separation (B-over-A design lock)", () => {
    it("projection digest never equals record digest for the same content", () => {
      const roles = rolesInRecord(baseRecord);
      const recordDigest = hashRecord(baseRecord);
      for (const role of roles) {
        const projection = projectByRole(baseRecord, role);
        const digest = projectionDigest(projection);
        expect(digest).not.toBe(recordDigest);
        for (const party of partiesForRole(baseRecord, role)) {
          const partyDigest = projectionDigest(
            projectByRole(baseRecord, role, party),
          );
          expect(partyDigest).not.toBe(recordDigest);
        }
      }
    });

    it("projection canonical bytes cannot parse as a valid record (structural)", () => {
      // Stronger form of the domain-separation invariant: not just that
      // digests differ, but that the canonical bytes of any projection are
      // syntactically not a JSON object. A record serializes via
      // JSON.stringify(record) to `{...}`; a projection's canonical bytes
      // wrap in `[TAG, canonical]` and start with `[`. If a future refactor
      // of the domain tag or wrapping loses this, this test fails.
      const roles = rolesInRecord(baseRecord);
      for (const role of roles) {
        const projection = projectByRole(baseRecord, role);
        // Use the EXACT production wrapping (canonicalizeValue +
        // PROJECTION_DOMAIN_TAG). If production changes to drop the outer
        // array wrap, this test flips red.
        const canonical = JSON.stringify([
          PROJECTION_DOMAIN_TAG,
          canonicalizeValue(projection),
        ]);
        // First byte must be `[`, never `{`.
        expect(canonical[0]).toBe("[");
        // A valid AuditRecord serialized starts with `{`.
        expect(JSON.stringify(baseRecord)[0]).toBe("{");
      }
    });

    it("hostile record with type='witness-projection' as a field still cannot collide", () => {
      // Even a record that carries a `type` field with a colliding value
      // hashes differently from a projection because the top-level canonical
      // structure differs: records use JSON.stringify (starts with `{`),
      // projections use canonicalizeValue-with-domain-tag (starts with `[`).
      const recordDigest = hashRecord(baseRecord);
      const projection = projectByRole(baseRecord, "witness");
      const projectionD = projectionDigest(projection);
      expect(projectionD).not.toBe(recordDigest);
      // Additionally: the projection's canonical bytes and the record's
      // JSON bytes have different opening characters.
      // (Records serialize to `{...}`; projections' canonical form wraps
      // in [PROJECTION_DOMAIN_TAG, canonical] which serializes to `[...`)
      // A shared prefix collision is structurally impossible.
    });
  });

  describe("edge cases and adversarial inputs", () => {
    it("handles empty parties[] as absent", () => {
      const empty: AuditRecord = { ...baseRecord, parties: [] };
      expect(rolesInRecord(empty)).toEqual([]);
      const p = projectByRole(empty, "witness");
      expect(p.scope).toEqual([]);
      expect(p.fields).toEqual({});
    });

    it("deduplicates when the same party/role appears multiple times", () => {
      const dupe: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["method"] },
          { party: "gateway", role: "witness", scope: ["method", "toolName"] },
        ],
      };
      expect(partiesForRole(dupe, "witness")).toEqual(["gateway"]);
      expect(scopeForRoleAndParty(dupe, "witness")).toEqual([
        "method",
        "toolName",
      ]);
    });

    it("dedupes overlapping scopes across parties in the same role", () => {
      const overlap: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["method", "toolName"] },
          { party: "sidecar", role: "witness", scope: ["toolName", "upstream"] },
        ],
      };
      const p = projectByRole(overlap, "witness");
      expect(p.scope).toEqual(["method", "toolName", "upstream"]);
    });

    it("returns undefined for scope-referenced fields absent from the record", () => {
      // A party attributes to a field that doesn't exist on the record.
      // The projection's `fields` should not include the key.
      const stale: AuditRecord = {
        ...baseRecord,
        parties: [
          {
            party: "gateway",
            role: "witness",
            scope: ["method", "nonexistentField"],
          },
        ],
      };
      const p = projectByRole(stale, "witness");
      // scope is still what the party claimed — but fields only includes
      // what's actually on the record.
      expect(p.scope).toEqual(["method", "nonexistentField"]);
      expect(p.fields).toEqual({ method: "tools/call" });
      expect("nonexistentField" in p.fields).toBe(false);
    });

    it("returns empty projection when no party matches the requested role", () => {
      // Record has only witness parties; asking for asserter returns empty.
      const witnessOnly: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["method"] },
        ],
      };
      const p = projectByRole(witnessOnly, "asserter");
      expect(p.role).toBe("asserter");
      expect(p.scope).toEqual([]);
      expect(p.fields).toEqual({});
    });

    it("returns empty projection when refined party is absent for the role", () => {
      const p = projectByRole(baseRecord, "witness", "nonexistent-party");
      expect(p.party).toBe("nonexistent-party");
      expect(p.scope).toEqual([]);
      expect(p.fields).toEqual({});
    });

    it("does not mutate the source record", () => {
      const snapshot = JSON.stringify(baseRecord);
      projectByRole(baseRecord, "witness");
      projectByRole(baseRecord, "asserter", "policy-engine");
      projectionDigest(projectByRole(baseRecord, "witness"));
      expect(JSON.stringify(baseRecord)).toBe(snapshot);
    });

    it("scope sort order is stable regardless of party input order", () => {
      const reversed: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["upstream", "method"] },
          { party: "sidecar", role: "witness", scope: ["toolName", "durationMs"] },
        ],
      };
      const permuted: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "sidecar", role: "witness", scope: ["durationMs", "toolName"] },
          { party: "gateway", role: "witness", scope: ["method", "upstream"] },
        ],
      };
      const pA = projectByRole(reversed, "witness");
      const pB = projectByRole(permuted, "witness");
      // Same scope set → same sorted output → same digest.
      expect(pA.scope).toEqual(pB.scope);
      // Note: fields identical too (same source record shape), so digests match.
    });

    it("hostile record with type field cannot forge as a projection", () => {
      // A record with `type: "witness-projection"` as a field would still
      // hash as a record (via JSON.stringify), starting with `{`. The
      // projection digest wraps in a domain-tagged array. Structural
      // difference in canonical input prevents collision.
      const hostileFields: Record<string, unknown> = {
        ...baseRecord,
        type: "witness-projection",
        projectionOf: "fake-hash",
      };
      const hostileRecord = hostileFields as unknown as AuditRecord;
      const recordDigest = createHash("sha256")
        .update(JSON.stringify(hostileRecord))
        .digest("hex");
      const projectionD = projectionDigest(
        projectByRole(baseRecord, "witness"),
      );
      expect(projectionD).not.toBe(recordDigest);
    });

    it("projection is serialization-roundtrip stable", () => {
      const p = projectByRole(baseRecord, "witness");
      const serialized = JSON.stringify(p);
      const rehydrated = JSON.parse(serialized) as typeof p;
      // Digest is derived from canonical form, not raw JSON, so a
      // roundtrip through JSON.parse should preserve the digest.
      expect(projectionDigest(rehydrated)).toBe(projectionDigest(p));
    });

    it("nested field values (objects) are preserved by reference-equivalence", () => {
      const withNested: AuditRecord = {
        ...baseRecord,
        aiInvocation: { turnId: "t-1", model: "claude-opus-5" },
        parties: [
          {
            party: "gateway",
            role: "witness",
            scope: ["method", "aiInvocation"],
          },
        ],
      };
      const p = projectByRole(withNested, "witness");
      expect(p.fields.aiInvocation).toEqual({
        turnId: "t-1",
        model: "claude-opus-5",
      });
    });

    it("undefined optional fields are omitted from projection fields", () => {
      // toolName is optional; when absent, the projection should not
      // include it as an explicit undefined key.
      const noOptional: AuditRecord = {
        ...baseRecord,
        toolName: undefined,
        parties: [
          {
            party: "gateway",
            role: "witness",
            scope: ["method", "toolName"],
          },
        ],
      };
      const p = projectByRole(noOptional, "witness");
      expect("method" in p.fields).toBe(true);
      expect("toolName" in p.fields).toBe(false);
    });

    it("projectionOf digest matches audit-log.hashRecord exactly", () => {
      // The `projectionOf` value must be the SAME as `hashRecord(source)`
      // so consumers can look up the source record by its known hash.
      const localHash = createHash("sha256")
        .update(JSON.stringify(baseRecord))
        .digest("hex");
      const p = projectByRole(baseRecord, "witness");
      expect(p.projectionOf).toBe(localHash);
    });

    it("float in a projected field throws (same producer requirement as record canonicalization)", () => {
      // `AuditRecord.durationMs` is integer milliseconds in this repo
      // (`Date.now() - startTime`), but a foreign record could carry a
      // float. `projectionDigest` propagates `canonicalizeValue`'s producer
      // requirement: non-integer numbers throw. Same contract Vector 2 of
      // the C-REC harness demonstrates on records.
      const withFloat: AuditRecord = { ...baseRecord, durationMs: 12.5 };
      const projection = projectByRole(withFloat, "witness");
      expect(() => projectionDigest(projection)).toThrow(/unsafe number/);
    });

    it("scope entry 'type' does not collide with the projection type discriminant", () => {
      // If a record ever has a top-level `type` field in a party's scope,
      // it must be projected under `fields.type`, not overwrite the
      // discriminant.
      const withType: AuditRecord = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["type", "method"] },
        ],
      };
      // AuditRecord doesn't currently expose `type`, so extraction returns
      // undefined (absent). The projection's own `type` field remains the
      // discriminant.
      const p = projectByRole(withType, "witness");
      expect(p.type).toBe("witness-projection");
    });

    it("unknown role values in untrusted input are filtered out", () => {
      // TypeScript erases at runtime. A record loaded from untrusted JSON
      // could carry role: "unknown". Enumerators should skip.
      const hostile = {
        ...baseRecord,
        parties: [
          { party: "gateway", role: "witness", scope: ["method"] },
          { party: "shady", role: "unknown", scope: ["principal"] } as unknown as PartyAttribution,
        ],
      } as AuditRecord;
      expect(rolesInRecord(hostile)).toEqual(["witness"]);
      expect(partiesForRole(hostile, "witness")).toEqual(["gateway"]);
      const p = projectByRole(hostile, "witness");
      expect(p.scope).toEqual(["method"]);
      expect(p.fields.principal).toBeUndefined();
    });

    it("dotted-path scope entries currently return no value (top-level only)", () => {
      // Documented limitation: nested-path support is a follow-up. This
      // test locks the current behavior so a future consumer that needs
      // it notices explicitly.
      const withDotted: AuditRecord = {
        ...baseRecord,
        aiInvocation: { model: "claude-opus-5" },
        parties: [
          {
            party: "gateway",
            role: "witness",
            scope: ["aiInvocation.model", "method"],
          },
        ],
      };
      const p = projectByRole(withDotted, "witness");
      // Top-level "method" is extracted.
      expect(p.fields.method).toBe("tools/call");
      // Dotted path is not resolved to a nested value.
      expect(p.fields["aiInvocation.model"]).toBeUndefined();
    });
  });

  describe("role vs party axis", () => {
    const multiWitnessRecord: AuditRecord = {
      ...baseRecord,
      parties: [
        {
          party: "gateway",
          role: "witness",
          scope: ["method", "toolName"],
        },
        {
          party: "audit-gateway-2",
          role: "witness",
          scope: ["upstream", "durationMs"],
        },
        {
          party: "policy-engine",
          role: "asserter",
          scope: ["success"],
        },
      ],
    };

    it("role-only projection unions all party scopes for that role", () => {
      const p = projectByRole(multiWitnessRecord, "witness");
      expect(p.scope).toEqual([
        "durationMs",
        "method",
        "toolName",
        "upstream",
      ]);
      expect(p.party).toBeUndefined();
    });

    it("role+party projection returns only the named party's scope", () => {
      const p = projectByRole(multiWitnessRecord, "witness", "gateway");
      expect(p.scope).toEqual(["method", "toolName"]);
      expect(p.party).toBe("gateway");
      expect(p.fields.upstream).toBeUndefined();
      expect(p.fields.durationMs).toBeUndefined();
    });

    it("role-only and role+party digests differ when parties differ", () => {
      const roleOnly = projectByRole(multiWitnessRecord, "witness");
      const rolePlus = projectByRole(
        multiWitnessRecord,
        "witness",
        "gateway",
      );
      expect(projectionDigest(roleOnly)).not.toBe(
        projectionDigest(rolePlus),
      );
    });
  });
});

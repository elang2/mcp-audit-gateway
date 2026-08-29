// Witness projection: deterministic role/party-scoped projection of an
// AuditRecord. Companion to the parties[] attribution on AuditRecord.
//
// Motivation: audit records carry multi-party attribution in `parties[]`
// (each entry has a role, party, and scope). Consumers that aggregate over
// records without respecting scope boundaries can silently collapse the
// witness-vs-asserter distinction. A dashboard counting "successful tool
// calls" without projecting to a scope creates the illusion that a host's
// self-attestation is as reliable as the gateway's independent
// observation.
//
// `projectByRole(record, role, party?)` returns a `WitnessProjection`, a
// type distinct from `AuditRecord`. That distinction is structural, so a
// consumer cannot mistake a projection for a record. The projection's
// canonical hash is domain-tagged so it cannot collide with a record hash
// by construction.
//
// Prior art on the read-side reduction problem:
//   - MCP SEP work on the parties/witness distinction identifies the
//     same failure mode from external runtimes: a type-level split
//     between "execution finished" (witnessed) and "execution reported"
//     (asserted) emerges after a consumer collapses the record-level
//     distinction under a counter.
//   - This repo's write-side regression tests assert that scope arrays
//     don't overlap and no cross-scope leakage occurs on ingest;
//     projectByRole is the read-side primitive that consumers call to
//     preserve those boundaries under aggregation.
//   - A separate SBOM-format proposal describes party-level field
//     attribution via native citation constructs; projectByRole is the
//     verifier-side projection primitive that shape implies.

import { createHash } from "node:crypto";
import type { AuditRecord, PartyAttribution } from "../types.js";
import { hashRecord } from "./audit-log.js";
import { canonicalizeValue } from "./signer.js";

export type PartyRole = PartyAttribution["role"];

/** Distinct type from AuditRecord. A projection cannot be mistaken for a
 * record by structure, by hashing domain, or by the type system. */
export interface WitnessProjection {
  /** Discriminant. Never matches any AuditRecord field. */
  type: "witness-projection";
  /** SHA-256 of the source record via `hashRecord` (raw `JSON.stringify`
   * + sha256, matching the chain's octets-first hashing of records).
   * Pointer back to the source. `projectionDigest`
   * below uses `canonicalizeValue` on the projection body itself; the
   * two hash outputs use different canonicalization disciplines
   * intentionally, so `projectionOf` matches chain lookups and
   * `projectionDigest` provides cross-implementation stability for the
   * projection value.
   * In-scope fields are preserved verbatim in `fields`; only out-of-scope
   * fields are dropped. */
  projectionOf: string;
  /** The role this projection covers. */
  role: PartyRole;
  /** Optional party refinement within the role. Absent means "all parties
   * with this role in the record." */
  party?: string;
  /** Field paths this projection covers, sorted deterministically. */
  scope: string[];
  /** Projected field values, keyed by field path. Only paths in `scope`
   * are present. */
  fields: Record<string, unknown>;
}

/** Domain tag applied to projection canonical bytes. Ensures the canonical
 * form differs structurally from any `JSON.stringify(record)` output.
 * Records serialize as `{...}`; projections wrap as `[...]` starting with
 * `[` plus this tag. Versioned so future projection shapes can be
 * introduced without silent digest collision. Exported so consumers can
 * verify without hardcoding. */
export const PROJECTION_DOMAIN_TAG = "WitnessProjection/v1";

const VALID_ROLES: ReadonlySet<PartyRole> = new Set(["witness", "asserter"]);

/** Enumerate distinct roles present in a record's parties[]. Filters out
 * any entry with an unknown role value (defensive against untrusted JSON
 * input where the TypeScript type erases at runtime). Sorted for
 * determinism. */
export function rolesInRecord(record: AuditRecord): PartyRole[] {
  if (!record.parties || record.parties.length === 0) return [];
  const seen = new Set<PartyRole>();
  for (const p of record.parties) {
    if (VALID_ROLES.has(p.role)) seen.add(p.role);
  }
  return Array.from(seen).sort() as PartyRole[];
}

/** Party names attributed with the given role in the record. Sorted. */
export function partiesForRole(
  record: AuditRecord,
  role: PartyRole,
): string[] {
  if (!record.parties) return [];
  const seen = new Set<string>();
  for (const p of record.parties) {
    if (!VALID_ROLES.has(p.role)) continue;
    if (p.role === role) seen.add(p.party);
  }
  return Array.from(seen).sort();
}

/** Union of field paths attributed to the given role (optionally further
 * refined by party). Sorted and deduplicated. */
export function scopeForRoleAndParty(
  record: AuditRecord,
  role: PartyRole,
  party?: string,
): string[] {
  if (!record.parties) return [];
  const seen = new Set<string>();
  for (const p of record.parties) {
    if (!VALID_ROLES.has(p.role)) continue;
    if (p.role !== role) continue;
    if (party !== undefined && p.party !== party) continue;
    for (const path of p.scope) seen.add(path);
  }
  return Array.from(seen).sort();
}

/** Project the record to the fields attributed to the given role
 * (optionally further refined by party). Returns a WitnessProjection
 * distinct from AuditRecord in type and in hashing domain.
 *
 * Deterministic: same input produces byte-identical output. Field paths
 * are top-level record keys. Nested-path support is a follow-up if a
 * consumer needs it.
 *
 * `projectionOf` is set to `hashRecord(record)` so the projection points
 * back to its source without carrying out-of-scope fields. In-scope fields
 * are preserved verbatim in `fields`.
 *
 * For deterministic equality between projections, compare via
 * `projectionDigest`, not `JSON.stringify` (the latter can reorder keys
 * across parse/serialize roundtrips). */
export function projectByRole(
  record: AuditRecord,
  role: PartyRole,
  party?: string,
): WitnessProjection {
  const scope = scopeForRoleAndParty(record, role, party);
  const fields: Record<string, unknown> = {};
  // Dynamic string-keyed access is intentional: scope paths are runtime
  // strings, not statically known field names. The double-cast is the
  // narrowest workaround.
  const anyRecord = record as unknown as Record<string, unknown>;
  for (const path of scope) {
    const value = anyRecord[path];
    if (value !== undefined) fields[path] = value;
  }
  return {
    type: "witness-projection",
    projectionOf: hashRecord(record),
    role,
    ...(party !== undefined ? { party } : {}),
    scope,
    fields,
  };
}

/** Deterministic canonical digest of a WitnessProjection. Domain-tagged so
 * it cannot collide with a record digest by construction: projection
 * canonical bytes are a JSON array starting with `["${PROJECTION_DOMAIN_TAG}",`
 * while record bytes (via `hashRecord`) are a JSON object starting with
 * `{`.
 *
 * Uses the shipped `canonicalizeValue` on the projection. This propagates
 * the same producer-requirement contract to projections that
 * `canonicalizeValue` enforces on records: non-integer numbers, unsafe
 * integers, and lone surrogates all throw. A caller who tries to project
 * a record whose field values violate that contract gets the same error
 * class Vector 2 of the C-REC harness demonstrates on records themselves.
 *
 * `durationMs` is currently assigned via `Date.now() - startTime` in every
 * production path (integer milliseconds by convention, not by type), so
 * it passes `canonicalizeValue`'s `Number.isSafeInteger` gate unchanged.
 * A future change to a float source (`performance.now()`, user-supplied
 * durations) would surface as an `unsafe number` throw here. Consumers
 * who ingest records from a different producer that emits floats must
 * string-encode at the boundary before calling `projectionDigest`. */
export function projectionDigest(projection: WitnessProjection): string {
  const canonical = canonicalizeValue(projection);
  const bytes = JSON.stringify([PROJECTION_DOMAIN_TAG, canonical]);
  return createHash("sha256").update(bytes).digest("hex");
}

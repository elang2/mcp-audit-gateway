#!/usr/bin/env node
// smoke-conformance.mjs
// ---------------------------------------------------------------------------
// Cross-SDK daemon-adversarial smoke test. Runs the fuzz-runner daemon
// protocol against each SDK's signer with two independent assertion phases,
// designed to catch "dead daemon" bugs — where a signer crashes or closes
// stdout mid-run and the outer harness silently loses responses — upfront,
// before Test A of the wider smoke procedure.
//
// The daemon protocol under test is the same one documented in
// ../fuzzing/fuzz-runner.mjs (verbatim summary below), and this script is
// the reference conformance check for it:
//
//   Startup env: DAEMON_MODE=1
//                CANONICAL_FORM=tuple-array | jcs
//                SIGNING_KEY_HEX=<64 hex chars>
//
//   Request  (one NDJSON line per record on daemon stdin):
//       {"id": "<opaque-string>", "record": <object>}
//
//   Response (one NDJSON line per request on daemon stdout):
//       {"id": "<same-id>", "ok": true,  "canonical": "<str>", "signature_hex": "<hex>"}
//     — or —
//       {"id": "<same-id>", "ok": false, "error": "<short-string>"}
//
//   Contract:
//     * Exactly one response line per request line.
//     * Response.id MUST equal request.id (echo, not reorder-only).
//     * On rejection, response MUST have {"ok": false, "error": <string>}.
//     * Daemon MUST stay alive until stdin EOF (no premature stdin close,
//       no stdout close, no process exit before the last response is
//       flushed).
//
// Phase layout:
//   Phase 0 — protocol-conformance (RUNS BEFORE Test A). Five hand-crafted
//     adversarial vectors, sent ONE AT A TIME per daemon, with an alive-
//     probe canary between vectors to confirm stdin is still open. If any
//     SDK drops a response, echoes the wrong id, sends {ok:false} without
//     an "error" string, or dies between vectors, that SDK is marked
//     FAIL and the whole smoke exits non-zero.
//
//   Phase A — bulk-38. Sends the full 38 hand-crafted vector corpus
//     (8 conformance + 5 nested + 25 adversarial) to each SDK's daemon,
//     then asserts response_count == request_count for every SDK. Any
//     dropped response is a hard FAIL for that SDK.
//
// Usage:
//   node smoke-conformance.mjs [--canonical-form=tuple-array|jcs]
//                              [--only=ts,py,go,...]
//                              [--phase=0|A|all]
// ---------------------------------------------------------------------------

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";

// ---------------------------------------------------------------------------
// Layout — script lives at test/vectors/smoke/smoke-conformance.mjs
// ---------------------------------------------------------------------------

const HERE = path.dirname(new URL(import.meta.url).pathname);
const VECTORS_ROOT = path.resolve(HERE, "..");
const MATRIX = path.join(VECTORS_ROOT, "cross-emitter-matrix");
const RUNNERS = path.join(VECTORS_ROOT, "runners");
const CANONICALIZATION_JSON = path.join(VECTORS_ROOT, "canonicalization.json");
const NESTED_JSON = path.join(MATRIX, "nested-vectors.json");
const ADVERSARIAL_JSON = path.join(MATRIX, "adversarial-vectors.json");

const DEFAULT_KEY_HEX =
  "0000000000000000000000000000000000000000000000000000000000000042";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let canonicalForm = "tuple-array";
let onlyLabels = null;
let phaseFilter = "all";
for (const arg of argv) {
  let m;
  if ((m = arg.match(/^--canonical-form=(tuple-array|jcs)$/))) {
    canonicalForm = m[1];
  } else if ((m = arg.match(/^--only=([a-z,]+)$/))) {
    onlyLabels = new Set(m[1].split(",").filter(Boolean));
  } else if ((m = arg.match(/^--phase=(0|A|all)$/))) {
    phaseFilter = m[1];
  } else if (arg === "-h" || arg === "--help") {
    console.error(
      "usage: smoke-conformance.mjs [--canonical-form=tuple-array|jcs]" +
        " [--only=ts,py,...] [--phase=0|A|all]",
    );
    process.exit(0);
  } else {
    console.error(`smoke-conformance: unknown arg ${arg}`);
    process.exit(2);
  }
}

const SIGNING_KEY_HEX = process.env.SIGNING_KEY_HEX || DEFAULT_KEY_HEX;
const RESPONSE_TIMEOUT_MS = Number.parseInt(
  process.env.SMOKE_RESPONSE_TIMEOUT_MS || "30000",
  10,
);
const BULK_TIMEOUT_MS = Number.parseInt(
  process.env.SMOKE_BULK_TIMEOUT_MS || "60000",
  10,
);

// ---------------------------------------------------------------------------
// SDK inventory (mirrors fuzz-runner.mjs). Kept inline so the smoke has no
// runtime dependency on the fuzzing module; if the lanes diverge in the
// future, this file is the smoke-side source of truth.
// ---------------------------------------------------------------------------

const JAVA_CP = [
  path.join(RUNNERS, "jackson-core.jar"),
  path.join(RUNNERS, "jackson-databind.jar"),
  path.join(RUNNERS, "jackson-annotations.jar"),
  MATRIX,
].join(":");
const KOTLIN_JCS_JAR = path.join(RUNNERS, "erdtman-canonicalize.jar");
const KOTLIN_CP_TUPLE = [
  path.join(RUNNERS, "jackson-core.jar"),
  path.join(RUNNERS, "jackson-databind.jar"),
  path.join(RUNNERS, "jackson-annotations.jar"),
].join(":");
const KOTLIN_CP_JCS = [KOTLIN_CP_TUPLE, KOTLIN_JCS_JAR].join(":");
const RUST_SIGN = path.join(MATRIX, "rust-signer/target/release/sign");
const RUST_SIGN_JCS = path.join(
  MATRIX,
  "rust-signer/target/release/sign_jcs_serde_jcs",
);
const CSHARP_SIGN_DLL = path.join(
  MATRIX,
  "csharp-signer/bin/Release/net9.0/Sign.dll",
);
const CSHARP_SIGN_JCS_DLL = path.join(
  MATRIX,
  "csharp-signer/bin/Release/net9.0/SignJcs.dll",
);
const DOTNET_BIN = path.join(process.env.HOME || "", ".dotnet/dotnet");

const SDK_LANES = {
  ts: {
    "tuple-array": { file: path.join(MATRIX, "sign.mjs"),
      argv: () => ["node", path.join(MATRIX, "sign.mjs")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.mjs"),
      argv: () => ["node", path.join(MATRIX, "sign-jcs.mjs")] },
  },
  py: {
    "tuple-array": { file: path.join(MATRIX, "sign.py"),
      argv: () => ["python3", "-u", path.join(MATRIX, "sign.py")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.py"),
      argv: () => ["python3", "-u", path.join(MATRIX, "sign-jcs.py")] },
  },
  go: {
    "tuple-array": { file: path.join(MATRIX, "sign.go"),
      argv: () => ["go", "run", path.join(MATRIX, "sign.go")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.go"),
      argv: () => ["go", "run", path.join(MATRIX, "sign-jcs.go")] },
  },
  rb: {
    "tuple-array": { file: path.join(MATRIX, "sign.rb"),
      argv: () => ["ruby", "-Ku", path.join(MATRIX, "sign.rb")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.rb"),
      argv: () => ["ruby", "-Ku", path.join(MATRIX, "sign-jcs.rb")] },
  },
  jv: {
    "tuple-array": { file: path.join(MATRIX, "Sign.class"),
      argv: () => ["java", "-cp", JAVA_CP, "Sign"] },
    jcs: { file: path.join(MATRIX, "SignJcs.class"),
      argv: () => ["java", "-cp", JAVA_CP, "SignJcs"] },
  },
  sw: {
    "tuple-array": { file: path.join(MATRIX, "sign.swift"),
      argv: () => ["swift", path.join(MATRIX, "sign.swift")],
      extraNeeds: () => process.platform === "darwin" },
    jcs: null,
  },
  ph: {
    "tuple-array": { file: path.join(MATRIX, "sign.php"),
      argv: () => ["php", path.join(MATRIX, "sign.php")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.php"),
      argv: () => ["php", path.join(MATRIX, "sign-jcs.php")] },
  },
  kt: {
    "tuple-array": { file: path.join(MATRIX, "sign.kts"),
      argv: () => ["kotlin", "-cp", KOTLIN_CP_TUPLE, path.join(MATRIX, "sign.kts")] },
    jcs: { file: path.join(MATRIX, "sign-jcs.kts"),
      argv: () => ["kotlin", "-cp", KOTLIN_CP_JCS, path.join(MATRIX, "sign-jcs.kts")] },
  },
  rs: {
    "tuple-array": { file: RUST_SIGN, argv: () => [RUST_SIGN] },
    jcs: { file: RUST_SIGN_JCS, argv: () => [RUST_SIGN_JCS] },
  },
  cs: {
    "tuple-array": { file: CSHARP_SIGN_DLL,
      argv: () => [DOTNET_BIN, CSHARP_SIGN_DLL],
      extraNeeds: () => existsSync(DOTNET_BIN) },
    jcs: { file: CSHARP_SIGN_JCS_DLL,
      argv: () => [DOTNET_BIN, CSHARP_SIGN_JCS_DLL],
      extraNeeds: () => existsSync(DOTNET_BIN) },
  },
};

const SDK_ORDER = ["ts", "py", "go", "rb", "jv", "sw", "ph", "kt", "rs", "cs"];

function buildSdkList(form) {
  const enabled = [];
  const skipped = [];
  for (const label of SDK_ORDER) {
    if (onlyLabels && !onlyLabels.has(label)) {
      skipped.push({ label, reason: "filtered by --only" });
      continue;
    }
    const lane = SDK_LANES[label] && SDK_LANES[label][form];
    if (!lane) { skipped.push({ label, reason: `no ${form} lane` }); continue; }
    let ok;
    try {
      ok = existsSync(lane.file) &&
        (typeof lane.extraNeeds !== "function" || lane.extraNeeds());
    } catch { ok = false; }
    if (!ok) { skipped.push({ label, reason: `missing ${lane.file}` }); continue; }
    enabled.push({ label, argv: lane.argv, file: lane.file });
  }
  return { enabled, skipped };
}

// ---------------------------------------------------------------------------
// Vector corpora
// ---------------------------------------------------------------------------

// The 5 protocol-conformance adversarial vectors. These are the inputs a
// well-behaved daemon MUST answer for — either with a signed canonical
// form or with {"ok": false, "error": <string>} — without dying.
//
// Rationale for each choice (short — long form in the return value):
//   pc-01 lone-surrogate     — string field with an unpaired UTF-16 high
//                              surrogate. JSON string that is not valid
//                              UTF-8 when re-encoded; forces the SDK's
//                              canonicalizer to either normalize/replace
//                              or reject rather than crash.
//   pc-02 int-past-2^53      — numeric field 9007199254740993, exactly
//                              one past JS Number.MAX_SAFE_INTEGER. Every
//                              SDK canonicalizer must either preserve as
//                              bignum or reject; silent double-precision
//                              rounding is a signed-payload bug.
//   pc-03 float              — numeric field 3.14. Some canonicalizers
//                              reject floats outright (integer-only
//                              schema); others emit them. Either verdict
//                              is fine for THIS phase; the assertion is
//                              only that a response line comes back.
//   pc-04 unsupported-type   — record contains a nested JSON `null` at
//                              a field the schema requires non-null.
//                              Exercises the daemon's schema-rejection
//                              path (must respond ok:false + error).
//   pc-05 malformed-utf-16   — string field with a REVERSED surrogate
//                              pair (\uDC00\uD800), i.e. low-then-high.
//                              This is malformed UTF-16 that cannot be
//                              transcoded to valid UTF-8; the daemon
//                              must respond (accept or reject), not hang
//                              or drop the line.
function conformanceVectors() {
  return [
    {
      id: "pc-01-lone-surrogate",
      category: "lone-surrogate",
      record: {
        id: "pc-01",
        timestamp: "2026-08-31T00:00:00.000Z",
        method: "tools/call",
        toolName: "smoke_lone_surrogate",
        namespace: "smoke",
        upstream: "smoke-svc",
        principal: "user:smoke\uD800@example.com",
        durationMs: 1,
        success: true,
        errorCode: null,
        previousHash: "genesis",
      },
    },
    {
      id: "pc-02-int-past-2p53",
      category: "integer-edge",
      record: {
        id: "pc-02",
        timestamp: "2026-08-31T00:00:01.000Z",
        method: "tools/call",
        toolName: "smoke_int_past_2p53",
        namespace: "smoke",
        upstream: "smoke-svc",
        principal: "user:smoke@example.com",
        durationMs: 9007199254740993, // Number.MAX_SAFE_INTEGER + 2
        success: true,
        errorCode: null,
        previousHash: "genesis",
      },
    },
    {
      id: "pc-03-float",
      category: "float",
      record: {
        id: "pc-03",
        timestamp: "2026-08-31T00:00:02.000Z",
        method: "tools/call",
        toolName: "smoke_float",
        namespace: "smoke",
        upstream: "smoke-svc",
        principal: "user:smoke@example.com",
        durationMs: 3.14,
        success: true,
        errorCode: null,
        previousHash: "genesis",
      },
    },
    {
      id: "pc-04-unsupported-type",
      category: "unsupported-type",
      record: {
        id: "pc-04",
        timestamp: "2026-08-31T00:00:03.000Z",
        method: "tools/call",
        toolName: null, // required-string field is null; must reject
        namespace: "smoke",
        upstream: "smoke-svc",
        principal: "user:smoke@example.com",
        durationMs: 1,
        success: true,
        errorCode: null,
        previousHash: "genesis",
      },
    },
    {
      id: "pc-05-malformed-utf-16",
      category: "malformed-utf-16",
      record: {
        id: "pc-05",
        timestamp: "2026-08-31T00:00:04.000Z",
        method: "tools/call",
        toolName: "smoke_reversed_pair_\uDC00\uD800",
        namespace: "smoke",
        upstream: "smoke-svc",
        principal: "user:smoke@example.com",
        durationMs: 1,
        success: true,
        errorCode: null,
        previousHash: "genesis",
      },
    },
  ];
}

// Alive-probe canary — a boringly valid tuple-array record every SDK
// signs happily. Sent between conformance vectors to check that the
// daemon didn't close stdin, close stdout, or exit after the pathological
// input. If the canary times out, the daemon is dead.
const CANARY_RECORD = {
  id: "pc-canary",
  timestamp: "2026-08-31T00:00:99.000Z",
  method: "tools/call",
  toolName: "smoke_canary",
  namespace: "smoke",
  upstream: "smoke-svc",
  principal: "user:canary@example.com",
  durationMs: 1,
  success: true,
  errorCode: null,
  previousHash: "genesis",
};

function bulkVectors() {
  const flat = JSON.parse(readFileSync(CANONICALIZATION_JSON, "utf-8"))
    .canonicalization.map((v) => v.record);
  const nested = JSON.parse(readFileSync(NESTED_JSON, "utf-8"))
    .vectors.map((v) => v.record);
  const adv = JSON.parse(readFileSync(ADVERSARIAL_JSON, "utf-8"))
    .vectors.map((v) => v.record);
  return [...flat, ...nested, ...adv];
}

// ---------------------------------------------------------------------------
// Daemon wrapper — a stripped-down version of fuzz-runner's SdkDaemon that
// exposes single-request sending (for phase 0) and burst dispatch with
// response-count assertion (for phase A).
// ---------------------------------------------------------------------------

class SdkDaemon {
  constructor(sdk) {
    this.sdk = sdk;
    this.label = sdk.label;
    this.pending = new Map(); // id → { resolve, timer }
    this.buf = "";
    this.dead = false;
    this.deathReason = null;
    this.proc = null;
    this.completed = 0;
    this.received = 0;   // total responses observed (any id)
    this.unmatched = 0;  // responses with no pending id
    this.malformed = 0;  // stdout lines that failed JSON parse
  }

  start() {
    const [cmd, ...args] = this.sdk.argv();
    try {
      this.proc = spawn(cmd, args, {
        cwd: MATRIX,
        env: {
          ...process.env,
          DAEMON_MODE: "1",
          CANONICAL_FORM: canonicalForm,
          SIGNING_KEY_HEX,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (e) { this._die(`spawn: ${e.message}`); return; }
    this.proc.stdout.setEncoding("utf-8");
    this.proc.stderr.setEncoding("utf-8");
    this.proc.stdout.on("data", (chunk) => this._onStdout(chunk));
    this.proc.stderr.on("data", (chunk) => {
      const trimmed = chunk.replace(/\s+$/, "");
      if (!trimmed) return;
      for (const line of trimmed.split("\n")) {
        if (line) console.error(`[${this.label}:stderr] ${line}`);
      }
    });
    this.proc.stdin.on("error", (e) => this._die(`stdin: ${e.message}`));
    this.proc.on("error", (e) => this._die(`proc-error: ${e.message}`));
    this.proc.on("close", (code, signal) => {
      this._die(`closed code=${code} signal=${signal}`);
    });
  }

  _onStdout(chunk) {
    this.buf += chunk;
    let idx;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, idx).trim();
      this.buf = this.buf.slice(idx + 1);
      if (!line) continue;
      this.received++;
      let msg;
      try { msg = JSON.parse(line); }
      catch {
        this.malformed++;
        console.error(`[${this.label}] non-json stdout: ${line.slice(0, 120)}`);
        continue;
      }
      if (!msg || typeof msg.id !== "string") {
        this.malformed++;
        console.error(`[${this.label}] response missing id: ${line.slice(0, 120)}`);
        continue;
      }
      const entry = this.pending.get(msg.id);
      if (!entry) { this.unmatched++; continue; }
      this.pending.delete(msg.id);
      clearTimeout(entry.timer);
      this.completed++;
      entry.resolve({ raw: msg });
    }
  }

  _die(reason) {
    if (this.dead) return;
    this.dead = true;
    this.deathReason = reason;
    console.error(`[${this.label}] daemon dead: ${reason}`);
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.resolve({ raw: null, deadReason: reason });
    }
    this.pending.clear();
    if (this.proc) { try { this.proc.kill("SIGKILL"); } catch {} }
  }

  isStdinWritable() {
    return !!(this.proc && this.proc.stdin && this.proc.stdin.writable);
  }

  request(id, record, timeoutMs) {
    if (this.dead) {
      return Promise.resolve({ raw: null, deadReason: this.deathReason || "dead" });
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.pending.delete(id);
        resolve({ raw: null, timeout: true, timeoutMs });
      }, timeoutMs);
      this.pending.set(id, { resolve, timer });
      const line = JSON.stringify({ id, record }) + "\n";
      try { this.proc.stdin.write(line); }
      catch (e) {
        this.pending.delete(id);
        clearTimeout(timer);
        this._die(`stdin write: ${e.message}`);
        resolve({ raw: null, deadReason: e.message });
      }
    });
  }

  shutdown() {
    if (!this.proc || this.dead) return;
    try { this.proc.stdin.end(); } catch {}
    const killer = setTimeout(() => { try { this.proc.kill("SIGKILL"); } catch {} }, 1000);
    this.proc.on("close", () => clearTimeout(killer));
  }
}

// ---------------------------------------------------------------------------
// Phase 0 — protocol-conformance
// ---------------------------------------------------------------------------
// For each SDK, one at a time:
//   for each of the 5 adversarial vectors:
//     1. Assert daemon stdin is still writable BEFORE dispatch.
//     2. Send the vector; wait up to RESPONSE_TIMEOUT_MS.
//     3. Assert exactly one response line was matched to this id
//        (SdkDaemon.request resolves on the first line with the matching
//        id; a second line with the same id would be counted as
//        unmatched and flagged).
//     4. Assert response.id === request.id (SdkDaemon ensures this
//        implicitly by keying pending on id; here we double-check on the
//        raw payload).
//     5. If response.ok === false, assert typeof response.error === "string"
//        and error.length > 0.
//     6. If response.ok === true, assert canonical is a non-empty string
//        and signature_hex is a hex string.
//     7. Send the CANARY_RECORD as a separate request with a fresh id
//        and wait up to RESPONSE_TIMEOUT_MS. If it times out or the
//        daemon is dead, mark this SDK's phase 0 as FAIL — the previous
//        vector killed it.
//   Assert daemon.received == 2 * (5) so far (5 adversarial + 5 canaries),
//   daemon.unmatched == 0, daemon.malformed == 0.

async function phase0(daemon, vectors) {
  const failures = [];
  const perVector = [];
  for (let i = 0; i < vectors.length; i++) {
    const v = vectors[i];
    if (!daemon.isStdinWritable()) {
      failures.push({ vector: v.id, reason: "stdin-not-writable-before-dispatch" });
      break;
    }
    const before = { received: daemon.received,
                     unmatched: daemon.unmatched,
                     malformed: daemon.malformed };
    const result = await daemon.request(v.id, v.record, RESPONSE_TIMEOUT_MS);
    const vectorReport = { vector: v.id, ok: null, verdict: null, error: null };

    if (result.deadReason) {
      failures.push({ vector: v.id, reason: `daemon-dead: ${result.deadReason}` });
      perVector.push({ ...vectorReport, verdict: "daemon-dead" });
      break;
    }
    if (result.timeout) {
      failures.push({ vector: v.id, reason: `timeout ${result.timeoutMs}ms` });
      perVector.push({ ...vectorReport, verdict: "timeout" });
      continue;
    }
    const msg = result.raw;
    // id echo
    if (msg.id !== v.id) {
      failures.push({ vector: v.id, reason: `id-mismatch response.id=${msg.id}` });
    }
    // exactly one response — check counters didn't jump by more than 1
    if (daemon.received !== before.received + 1) {
      failures.push({
        vector: v.id,
        reason: `expected received+1 got +${daemon.received - before.received}`,
      });
    }
    if (daemon.unmatched !== before.unmatched) {
      failures.push({
        vector: v.id,
        reason: `unmatched grew from ${before.unmatched} to ${daemon.unmatched}`,
      });
    }
    if (daemon.malformed !== before.malformed) {
      failures.push({
        vector: v.id,
        reason: `malformed grew from ${before.malformed} to ${daemon.malformed}`,
      });
    }
    // ok shape
    if (msg.ok === true) {
      if (typeof msg.canonical !== "string" || msg.canonical.length === 0) {
        failures.push({ vector: v.id, reason: "ok:true missing canonical string" });
      }
      if (typeof msg.signature_hex !== "string" ||
          !/^[0-9a-fA-F]+$/.test(msg.signature_hex)) {
        failures.push({ vector: v.id, reason: "ok:true missing hex signature_hex" });
      }
      vectorReport.verdict = "accepted";
    } else if (msg.ok === false) {
      if (typeof msg.error !== "string" || msg.error.length === 0) {
        failures.push({ vector: v.id, reason: "ok:false without error string" });
      }
      vectorReport.verdict = "rejected";
      vectorReport.error = typeof msg.error === "string" ? msg.error : null;
    } else {
      failures.push({ vector: v.id, reason: `ok field is neither true nor false: ${JSON.stringify(msg.ok)}` });
      vectorReport.verdict = "malformed-ok";
    }
    vectorReport.ok = msg.ok === true;
    perVector.push(vectorReport);

    // Alive canary — must still respond after the pathological input.
    const canaryId = `pc-canary-${i}`;
    const canary = await daemon.request(canaryId, CANARY_RECORD, RESPONSE_TIMEOUT_MS);
    if (canary.deadReason) {
      failures.push({ vector: v.id, reason: `canary: daemon-dead ${canary.deadReason}` });
      break;
    }
    if (canary.timeout) {
      failures.push({ vector: v.id, reason: "canary: timeout — daemon stopped responding" });
      break;
    }
    if (!canary.raw || canary.raw.id !== canaryId) {
      failures.push({ vector: v.id, reason: "canary: id mismatch" });
      break;
    }
    if (canary.raw.ok !== true) {
      failures.push({
        vector: v.id,
        reason: `canary rejected: ${canary.raw.error || "no-error-field"}`,
      });
      break;
    }
  }
  return {
    pass: failures.length === 0,
    failures,
    perVector,
    counters: {
      received: daemon.received,
      unmatched: daemon.unmatched,
      malformed: daemon.malformed,
      dead: daemon.dead,
      deathReason: daemon.deathReason,
    },
  };
}

// ---------------------------------------------------------------------------
// Phase A — bulk-38 with strict response-count assertion.
// ---------------------------------------------------------------------------

async function phaseA(daemon, vectors) {
  // Send all 38 requests without waiting; daemon must respond to each.
  const pending = vectors.map((rec, i) => {
    const id = `bulk-${i.toString().padStart(3, "0")}`;
    return daemon.request(id, rec, BULK_TIMEOUT_MS).then((r) => ({ id, r }));
  });
  const results = await Promise.all(pending);

  const requestCount = results.length;
  const timeoutCount = results.filter((x) => x.r.timeout).length;
  const deadCount = results.filter((x) => x.r.deadReason).length;
  const responseCount = results.filter((x) => x.r.raw).length;

  const failures = [];
  if (responseCount !== requestCount) {
    failures.push({
      reason: `response_count ${responseCount} != request_count ${requestCount}` +
        ` (timeouts=${timeoutCount}, dead=${deadCount})`,
    });
  }
  // Also cross-check with daemon counters — a duplicate response for a
  // single id would raise unmatched above 0 without necessarily bumping
  // "completed" for the pending id.
  if (daemon.unmatched > 0) {
    failures.push({ reason: `unmatched responses: ${daemon.unmatched}` });
  }
  if (daemon.malformed > 0) {
    failures.push({ reason: `malformed stdout lines: ${daemon.malformed}` });
  }

  return {
    pass: failures.length === 0,
    failures,
    requestCount,
    responseCount,
    timeoutCount,
    deadCount,
  };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

async function main() {
  const { enabled: SDKS, skipped } = buildSdkList(canonicalForm);
  if (SDKS.length === 0) {
    console.error("smoke-conformance: no SDKs enabled after filter/existence check");
    for (const s of skipped) console.error(`  skipped ${s.label}: ${s.reason}`);
    process.exit(2);
  }

  console.error(
    `smoke-conformance: canonical-form=${canonicalForm}, ` +
      `${SDKS.length} SDKs enabled: ${SDKS.map((s) => s.label).join(", ")}`,
  );
  for (const s of SDKS) {
    console.error(`  [${s.label}] binary=${s.file}`);
  }
  if (skipped.length) {
    console.error(
      `smoke-conformance: skipped ${skipped.length}: ${skipped.map((s) => `${s.label}(${s.reason})`).join(", ")}`,
    );
  }

  const confVectors = conformanceVectors();
  const bulk = bulkVectors();
  console.error(
    `smoke-conformance: ${confVectors.length} conformance vectors, ${bulk.length} bulk vectors`,
  );

  const report = {
    canonical_form: canonicalForm,
    started_at: new Date().toISOString(),
    sdks: {},
  };
  let overallPass = true;

  // Phase 0 first, one SDK at a time. Each SDK gets its own daemon spawn
  // so a phase-0 kill of one SDK doesn't leak into another SDK's phase A.
  if (phaseFilter === "0" || phaseFilter === "all") {
    for (const sdk of SDKS) {
      const daemon = new SdkDaemon(sdk);
      daemon.start();
      // Give slow JVMs / dotnet a moment to boot before first write.
      await sleep(250);
      const p0 = await phase0(daemon, confVectors);
      report.sdks[sdk.label] = { phase0: p0 };
      daemon.shutdown();
      if (!p0.pass) {
        overallPass = false;
        console.error(
          `[${sdk.label}] PHASE 0 FAIL: ${p0.failures.map((f) => `${f.vector}: ${f.reason}`).join("; ")}`,
        );
      } else {
        console.error(`[${sdk.label}] phase 0 pass`);
      }
    }
  }

  // Phase A — bulk-38 with response-count assertion. Fresh daemon per SDK.
  if (phaseFilter === "A" || phaseFilter === "all") {
    for (const sdk of SDKS) {
      const daemon = new SdkDaemon(sdk);
      daemon.start();
      await sleep(250);
      const pA = await phaseA(daemon, bulk);
      const entry = report.sdks[sdk.label] || {};
      entry.phaseA = pA;
      report.sdks[sdk.label] = entry;
      daemon.shutdown();
      if (!pA.pass) {
        overallPass = false;
        console.error(
          `[${sdk.label}] PHASE A FAIL (req=${pA.requestCount} resp=${pA.responseCount} timeout=${pA.timeoutCount} dead=${pA.deadCount}): ${pA.failures.map((f) => f.reason).join("; ")}`,
        );
      } else {
        console.error(
          `[${sdk.label}] phase A pass (${pA.responseCount}/${pA.requestCount})`,
        );
      }
    }
  }

  report.ended_at = new Date().toISOString();
  report.pass = overallPass;
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(overallPass ? 0 : 1);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch((e) => {
  console.error(`smoke-conformance: fatal ${e && e.stack ? e.stack : e}`);
  process.exit(2);
});

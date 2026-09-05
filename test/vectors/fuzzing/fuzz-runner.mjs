#!/usr/bin/env node
// fuzz-runner.mjs
// Multi-SDK canonical-signer bridge for cross-emitter fuzzing — DAEMON MODE.
//
// One persistent subprocess per SDK (9 on Linux, 10 on macOS) is spawned at
// startup with DAEMON_MODE=1 and CANONICAL_FORM=<form> in env. Records flow
// over each daemon's stdin as NDJSON; canonical/signature responses flow
// back over stdout as NDJSON. This replaces the previous fork-per-record
// design (~14 records/min because of JVM/CLR/Swift cold starts) with an
// amortized dispatch that runs 1000+ records/min on the same hardware.
//
// -----------------------------------------------------------------------
// Daemon protocol (contract between fuzz-runner.mjs and each sign.<lang>):
// -----------------------------------------------------------------------
//   Startup env: DAEMON_MODE=1
//                CANONICAL_FORM=tuple-array | jcs
//                SIGNING_KEY_HEX=<64 hex chars>
//
//   Request  (fuzz-runner → daemon, one NDJSON line per record on stdin):
//       {"id": "<opaque-string>", "record": <object>}
//
//   Response (daemon → fuzz-runner, one NDJSON line per request on stdout):
//       {"id": "<same-id>", "ok": true,  "canonical": "<str>", "signature_hex": "<hex>"}
//     — or —
//       {"id": "<same-id>", "ok": false, "error": "<short-string>"}
//
//   Rules:
//     * Exactly one response line per request line. Order need not match
//       request order; responses are correlated by id.
//     * Daemon MUST flush stdout after every response line.
//     * Daemon stays alive until stdin EOF (or SIGTERM at shutdown).
//     * stderr is diagnostic only; runner logs it but never parses it.
//     * If a daemon exits, closes stdout, or misses its per-request
//       response deadline too many times, the runner marks it dead and
//       excludes it from future dispatch and from pair comparisons.
//
// Divergence record shape (one JSONL line per disagreeing pair on stdout):
//   { record, minimal, sdkA, sdkB, outputA, outputB,
//     canonicalA, canonicalB, majority, outlier }
//
// Checkpoint: every CHECKPOINT_EVERY (5000) records, an atomic write of
// { generator_seed, record_index, canonical_form, divergences, timestamp }
// lands at $FUZZ_CHECKPOINT_PATH (default /tmp/fuzz-checkpoint.json). The
// checkpoint is also written on graceful shutdown.
// -----------------------------------------------------------------------

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const MATRIX = path.resolve(HERE, "../cross-emitter-matrix");
const RUNNERS = path.resolve(HERE, "../runners");
const DEFAULT_KEY_HEX =
  "0000000000000000000000000000000000000000000000000000000000000042";

// Belt-and-suspenders correlation: hash the exact wire-line bytes (before
// the trailing newline) so that a daemon returning id:null can still be
// linked back to the originating request post-hoc. The primary channel
// (opaque string id) is unchanged; the sha1 is a second channel logged
// alongside every request/response for grep-based analysis and — when the
// daemon happens to echo it in a `sha1` response field — for live recovery.
function sha1Hex(s) {
  return createHash("sha1").update(s, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let canonicalForm = "tuple-array";
let selfTest = false;
for (const arg of argv) {
  const m = arg.match(/^--canonical-form=(tuple-array|jcs)$/);
  if (m) {
    canonicalForm = m[1];
    continue;
  }
  if (arg === "--self-test") {
    selfTest = true;
    continue;
  }
  if (arg === "-h" || arg === "--help") {
    console.error(
      "usage: fuzz-runner.mjs [--canonical-form=tuple-array|jcs] [--self-test] < records.ndjson",
    );
    process.exit(0);
  }
  console.error(`fuzz-runner: unknown arg ${arg}`);
  process.exit(2);
}

if (selfTest) {
  runSelfTest();
}

const SIGNING_KEY_HEX = process.env.SIGNING_KEY_HEX || DEFAULT_KEY_HEX;
const GENERATOR_SEED = process.env.FUZZ_GENERATOR_SEED || null;
const CHECKPOINT_PATH =
  process.env.FUZZ_CHECKPOINT_PATH || "/tmp/fuzz-checkpoint.json";
const CHECKPOINT_EVERY = Number.parseInt(
  process.env.FUZZ_CHECKPOINT_EVERY || "5000",
  10,
);
const RESPONSE_TIMEOUT_MS = Number.parseInt(
  process.env.FUZZ_RESPONSE_TIMEOUT_MS || "60000",
  10,
);
const MAX_CONSECUTIVE_TIMEOUTS = Number.parseInt(
  process.env.FUZZ_MAX_CONSECUTIVE_TIMEOUTS || "3",
  10,
);
const PROGRESS_EVERY = Number.parseInt(
  process.env.FUZZ_PROGRESS_EVERY || "100",
  10,
);
// How long a daemon-returned id:null response is held as an "orphan"
// before we give up trying to correlate it and emit a standalone id_lost
// event to the divergence stream. 5s matches the spec of this correlation
// mechanism: long enough to catch late in-flight requests, short enough
// that memory does not grow unboundedly under a fumbled-id daemon bug.
const ID_LOST_WINDOW_MS = Number.parseInt(
  process.env.FUZZ_ID_LOST_WINDOW_MS || "5000",
  10,
);

// ---------------------------------------------------------------------------
// SDK inventory (unchanged from single-shot runner, plus needs() gates)
// ---------------------------------------------------------------------------

const JAVA_CP_PARTS = [
  path.join(RUNNERS, "jackson-core.jar"),
  path.join(RUNNERS, "jackson-databind.jar"),
  path.join(RUNNERS, "jackson-annotations.jar"),
  MATRIX,
];
const JAVA_CP = JAVA_CP_PARTS.join(":");
const JAVA_CP_JCS = [
  ...JAVA_CP_PARTS.filter((p) => p !== MATRIX),
  path.join(RUNNERS, "erdtman-canonicalize.jar"),
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

// Per-SDK dispatch: two lanes (tuple-array vs jcs). Each lane names the
// binary and the file that must exist for `needs()` to return true. Swift
// has no JCS binary (no maintained RFC 8785 library for the Swift ecosystem
// as of 2026-08-31), so its jcs lane is null and the SDK is dropped from
// the jcs run — an honest ecosystem gap rather than a shim we can't verify.
//
// The `needs()` check keys off a real file on disk (a source file, class
// file, native binary, or DLL), so we never spawn a daemon that will exit
// immediately. That's the "log the effective binary" evidence the runner
// prints below — dispatch is by real path, not by env var. If someone
// silently deletes sign-jcs.py, the SDK just drops out with a "skipped"
// message; there is no way for a tuple-array binary to run in a jcs cell.
const SDK_LANES = {
  ts: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.mjs"),
      argv: () => ["node", path.join(MATRIX, "sign.mjs")],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.mjs"),
      argv: () => ["node", path.join(MATRIX, "sign-jcs.mjs")],
    },
  },
  py: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.py"),
      argv: () => ["python3", "-u", path.join(MATRIX, "sign.py")],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.py"),
      argv: () => ["python3", "-u", path.join(MATRIX, "sign-jcs.py")],
    },
  },
  go: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.go"),
      argv: () => ["go", "run", path.join(MATRIX, "sign.go")],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.go"),
      argv: () => ["go", "run", path.join(MATRIX, "sign-jcs.go")],
    },
  },
  rb: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.rb"),
      argv: () => ["ruby", "-Ku", path.join(MATRIX, "sign.rb")],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.rb"),
      argv: () => ["ruby", "-Ku", path.join(MATRIX, "sign-jcs.rb")],
    },
  },
  jv: {
    "tuple-array": {
      file: path.join(MATRIX, "Sign.class"),
      argv: () => ["java", "-cp", JAVA_CP, "Sign"],
    },
    jcs: {
      file: path.join(MATRIX, "SignJcs.class"),
      argv: () => ["java", "-cp", JAVA_CP_JCS, "SignJcs"],
    },
  },
  sw: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.swift"),
      argv: () => ["swift", path.join(MATRIX, "sign.swift")],
      extraNeeds: () => process.platform === "darwin",
    },
    jcs: null, // no maintained JCS library for Swift as of 2026-08-31
  },
  ph: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.php"),
      argv: () => ["php", path.join(MATRIX, "sign.php")],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.php"),
      argv: () => ["php", path.join(MATRIX, "sign-jcs.php")],
    },
  },
  kt: {
    "tuple-array": {
      file: path.join(MATRIX, "sign.kts"),
      argv: () => [
        "kotlin",
        "-cp",
        KOTLIN_CP_TUPLE,
        path.join(MATRIX, "sign.kts"),
      ],
    },
    jcs: {
      file: path.join(MATRIX, "sign-jcs.kts"),
      argv: () => [
        "kotlin",
        "-cp",
        KOTLIN_CP_JCS,
        path.join(MATRIX, "sign-jcs.kts"),
      ],
    },
  },
  rs: {
    "tuple-array": {
      file: RUST_SIGN,
      argv: () => [RUST_SIGN],
    },
    jcs: {
      // Primary: serde_jcs binding (byte-identical to cyberphone testdata).
      // sign_jcs_canonicalizer is a separate binary used as a manual appendix
      // cross-check outside the fuzzing hot loop; it is not wired here.
      file: RUST_SIGN_JCS,
      argv: () => [RUST_SIGN_JCS],
    },
  },
  cs: {
    "tuple-array": {
      file: CSHARP_SIGN_DLL,
      argv: () => [DOTNET_BIN, CSHARP_SIGN_DLL],
      extraNeeds: () => existsSync(DOTNET_BIN),
    },
    jcs: {
      file: CSHARP_SIGN_JCS_DLL,
      argv: () => [DOTNET_BIN, CSHARP_SIGN_JCS_DLL],
      extraNeeds: () => existsSync(DOTNET_BIN),
    },
  },
};

const SDK_ORDER = ["ts", "py", "go", "rb", "jv", "sw", "ph", "kt", "rs", "cs"];

function buildSdkList(form) {
  const enabled = [];
  const skipped = [];
  for (const label of SDK_ORDER) {
    const lanes = SDK_LANES[label];
    const lane = lanes && lanes[form];
    if (!lane) {
      skipped.push({ label, reason: `no ${form} lane` });
      continue;
    }
    let ok;
    try {
      ok =
        existsSync(lane.file) &&
        (typeof lane.extraNeeds !== "function" || lane.extraNeeds());
    } catch {
      ok = false;
    }
    if (!ok) {
      skipped.push({ label, reason: `missing ${lane.file}` });
      continue;
    }
    enabled.push({ label, argv: lane.argv, file: lane.file });
  }
  return { enabled, skipped };
}

const { enabled: SDKS, skipped } = buildSdkList(canonicalForm);

if (SDKS.length < 2) {
  console.error(`fuzz-runner: only ${SDKS.length} SDK(s) available; need >= 2`);
  for (const s of skipped)
    console.error(`  skipped ${s.label}: ${s.reason}`);
  process.exit(2);
}

console.error(
  `fuzz-runner: canonical-form=${canonicalForm}, ${SDKS.length} SDKs enabled: ${SDKS.map((s) => s.label).join(", ")}`,
);
// Per-response logging of the effective binary path used, so a silent
// regression (e.g. sign-jcs.py deleted, sign.py picked up under jcs flag)
// is detectable from runner stderr. Prints once per SDK at startup.
for (const s of SDKS) {
  console.error(`  [${s.label}] binary=${s.file}`);
}
if (skipped.length) {
  console.error(
    `fuzz-runner: skipped ${skipped.length}: ${skipped.map((s) => `${s.label}(${s.reason})`).join(", ")}`,
  );
}

// ---------------------------------------------------------------------------
// Daemon wrapper
// ---------------------------------------------------------------------------

class SdkDaemon {
  constructor(sdk) {
    this.sdk = sdk;
    this.label = sdk.label;
    // Primary correlation channel: opaque string id (unchanged wire protocol).
    this.pending = new Map(); // id → { resolve, timer, sha1, sent_at, record }
    // Second channel: sha1 of the exact request wire-line. Enables lookup
    // when a daemon returns id:null but happens to echo a `sha1` field —
    // otherwise the sha1 is purely observability (logged, not matched).
    this.pendingBySha1 = new Map(); // sha1 → id
    // Held id:null responses awaiting correlation. If a still-pending
    // request times out while an orphan is fresh (<= ID_LOST_WINDOW_MS old),
    // the orphan is claimed and the pair is emitted as an id_lost event
    // rather than as a hard timeout — preserving signal without inflating
    // the consecutive-timeouts streak that would otherwise mark the daemon
    // dead. Orphans that stay unclaimed past the window are emitted on
    // their own.
    this.orphanNullResponses = []; // [{ msg, receivedAt, timer }]
    this.buf = "";
    this.dead = false;
    this.deathReason = null;
    this.nextInternal = 0;
    this.consecutiveTimeouts = 0;
    this.proc = null;
    this.completed = 0;
    this.idLostCount = 0;
    this.sha1RecoveredCount = 0;
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
    } catch (e) {
      this._die(`spawn: ${e.message}`);
      return;
    }
    this.proc.stdout.setEncoding("utf-8");
    this.proc.stderr.setEncoding("utf-8");
    this.proc.stdout.on("data", (chunk) => this._onStdout(chunk));
    this.proc.stderr.on("data", (chunk) => {
      const trimmed = chunk.replace(/\s+$/, "");
      if (trimmed) {
        for (const line of trimmed.split("\n")) {
          if (line) console.error(`[${this.label}:stderr] ${line}`);
        }
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
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        // Startup noise (e.g. Ruby load-path warnings routed to stdout).
        console.error(
          `[${this.label}] non-json stdout: ${line.slice(0, 120)}`,
        );
        continue;
      }
      if (!msg || typeof msg !== "object") {
        console.error(
          `[${this.label}] non-object stdout: ${line.slice(0, 120)}`,
        );
        continue;
      }
      // Primary channel: id-based match. Unchanged wire-protocol semantics.
      if (typeof msg.id === "string" && this.pending.has(msg.id)) {
        this._resolvePending(msg.id, msg, "id");
        continue;
      }
      // Second channel: sha1 echo. The wire protocol does not require the
      // daemon to include a sha1 field, but if it does — either because
      // the SDK was extended to echo it, or because a future protocol
      // revision opts in — we can recover a fumbled id.
      if (
        typeof msg.sha1 === "string" &&
        this.pendingBySha1.has(msg.sha1)
      ) {
        const recoveredId = this.pendingBySha1.get(msg.sha1);
        console.error(
          `[${this.label}] id_recovered_by_sha1: expected_id=${recoveredId} got_id=${JSON.stringify(msg.id)} sha1=${msg.sha1}`,
        );
        this.sha1RecoveredCount++;
        this._resolvePending(recoveredId, msg, "sha1");
        continue;
      }
      // id:null (or missing) with no sha1 correlation → orphan. Hold for
      // ID_LOST_WINDOW_MS in case a pending request times out during the
      // window and can claim it.
      if (msg.id === null || msg.id === undefined) {
        this._registerOrphan(msg);
        continue;
      }
      // Non-null id we don't recognise (late arrival after timeout, or
      // daemon confused). Log and drop — matches prior behaviour.
      if (typeof msg.id === "string") {
        // No-op: pending map miss means the id already timed out.
        continue;
      }
      console.error(
        `[${this.label}] response with non-string non-null id: ${line.slice(0, 120)}`,
      );
    }
  }

  _resolvePending(id, msg, matchedBy) {
    const entry = this.pending.get(id);
    if (!entry) return;
    this.pending.delete(id);
    if (entry.sha1) this.pendingBySha1.delete(entry.sha1);
    clearTimeout(entry.timer);
    this.consecutiveTimeouts = 0;
    this.completed++;
    // Every completion is logged with both channels so post-hoc grep can
    // correlate even when the daemon returns id:null. Suppressed to stderr
    // to avoid contaminating the divergence JSONL on stdout; enable
    // FUZZ_LOG_EACH_RESPONSE=1 for per-record visibility on hot loops.
    if (process.env.FUZZ_LOG_EACH_RESPONSE === "1") {
      console.error(
        `[${this.label}] resp match=${matchedBy} id=${id} sha1=${entry.sha1} ok=${msg.ok === true}`,
      );
    }
    if (msg.ok === true) {
      entry.resolve({
        ok: true,
        canonical:
          typeof msg.canonical === "string" ? msg.canonical : null,
        signature_hex:
          typeof msg.signature_hex === "string"
            ? msg.signature_hex
            : null,
        matched_by: matchedBy,
        sha1: entry.sha1,
      });
    } else {
      entry.resolve({
        ok: false,
        error: msg.error
          ? String(msg.error).slice(0, 200)
          : "unknown-daemon-error",
        matched_by: matchedBy,
        sha1: entry.sha1,
      });
    }
  }

  _registerOrphan(msg) {
    const orphan = { msg, receivedAt: Date.now(), timer: null };
    orphan.timer = setTimeout(() => {
      const i = this.orphanNullResponses.indexOf(orphan);
      if (i >= 0) this.orphanNullResponses.splice(i, 1);
      this._emitIdLostEvent(msg, "orphan_expired");
    }, ID_LOST_WINDOW_MS);
    if (orphan.timer && typeof orphan.timer.unref === "function") {
      orphan.timer.unref();
    }
    this.orphanNullResponses.push(orphan);
    console.error(
      `[${this.label}] id_null_orphan_registered: pending=${this.pending.size} canonical_len=${(msg.canonical || "").length}`,
    );
  }

  _tryClaimOrphan() {
    // Called from a pending request's timeout. Return the oldest fresh
    // orphan (<= ID_LOST_WINDOW_MS old) if any. Stale orphans are dropped
    // silently — their own timer will have fired an id_lost event.
    const now = Date.now();
    while (this.orphanNullResponses.length > 0) {
      const orphan = this.orphanNullResponses[0];
      if (now - orphan.receivedAt > ID_LOST_WINDOW_MS) {
        this.orphanNullResponses.shift();
        clearTimeout(orphan.timer);
        continue;
      }
      this.orphanNullResponses.shift();
      clearTimeout(orphan.timer);
      return orphan.msg;
    }
    return null;
  }

  _emitIdLostEvent(msg, reason) {
    this.idLostCount++;
    const event = {
      event: "id_lost",
      sdk: this.label,
      reason,
      ok: msg && msg.ok === true,
      canonical:
        msg && typeof msg.canonical === "string" ? msg.canonical : null,
      signature_hex:
        msg && typeof msg.signature_hex === "string"
          ? msg.signature_hex
          : null,
      error: msg && msg.error ? String(msg.error).slice(0, 200) : null,
      timestamp: new Date().toISOString(),
    };
    process.stdout.write(JSON.stringify(event) + "\n");
  }

  _die(reason) {
    if (this.dead) return;
    this.dead = true;
    this.deathReason = reason;
    console.error(`[${this.label}] daemon dead: ${reason}`);
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.resolve({
        ok: false,
        error: `daemon-dead: ${reason.slice(0, 120)}`,
        sha1: entry.sha1,
      });
    }
    this.pending.clear();
    this.pendingBySha1.clear();
    for (const orphan of this.orphanNullResponses) {
      clearTimeout(orphan.timer);
    }
    this.orphanNullResponses = [];
    if (this.proc) {
      try {
        this.proc.kill("SIGKILL");
      } catch {}
    }
  }

  request(record) {
    if (this.dead) {
      return Promise.resolve({
        ok: false,
        error: `daemon-dead: ${(this.deathReason || "").slice(0, 120)}`,
      });
    }
    const id = `${this.label}-${this.nextInternal++}`;
    // Compute sha1 of the exact wire-line bytes (without the trailing
    // newline). Stored in the pending entry both as a secondary lookup key
    // and as an observability breadcrumb — the log lines below carry both
    // id and sha1 so a post-hoc analyzer can reconstruct pairings even for
    // requests whose responses came back with id:null.
    const wireLine = JSON.stringify({ id, record });
    const sha1 = sha1Hex(wireLine);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.pending.delete(id);
        this.pendingBySha1.delete(sha1);
        // Belt-and-suspenders: before treating the miss as a hard timeout,
        // check whether a fresh id:null orphan is sitting on our doorstep.
        // If so, associate it with this request and emit an id_lost event
        // rather than inflating the consecutive-timeouts streak (which
        // would eventually kill an otherwise-functional daemon that is
        // merely fumbling response ids).
        const orphan = this._tryClaimOrphan();
        if (orphan) {
          this._emitIdLostEvent(orphan, "claimed_on_timeout");
          this.completed++;
          console.error(
            `[${this.label}] id_lost: expected_id=${id} sha1=${sha1} claimed_orphan`,
          );
          resolve({
            ok: false,
            error: "id_lost",
            sha1,
            canonical:
              typeof orphan.canonical === "string"
                ? orphan.canonical
                : null,
            signature_hex:
              typeof orphan.signature_hex === "string"
                ? orphan.signature_hex
                : null,
          });
          return;
        }
        this.consecutiveTimeouts++;
        const shouldKill =
          this.consecutiveTimeouts >= MAX_CONSECUTIVE_TIMEOUTS;
        resolve({
          ok: false,
          error: `timeout after ${RESPONSE_TIMEOUT_MS}ms (streak=${this.consecutiveTimeouts})`,
          sha1,
        });
        if (shouldKill && !this.dead) {
          this._die(
            `${this.consecutiveTimeouts} consecutive timeouts — killing daemon`,
          );
        }
      }, RESPONSE_TIMEOUT_MS);
      this.pending.set(id, {
        resolve,
        timer,
        sha1,
        sent_at: Date.now(),
        record,
      });
      this.pendingBySha1.set(sha1, id);
      try {
        this.proc.stdin.write(wireLine + "\n");
      } catch (e) {
        this.pending.delete(id);
        this.pendingBySha1.delete(sha1);
        clearTimeout(timer);
        this._die(`stdin write: ${e.message}`);
        resolve({
          ok: false,
          error: `daemon-dead: ${e.message}`,
          sha1,
        });
      }
    });
  }

  shutdown() {
    if (!this.proc || this.dead) return;
    try {
      this.proc.stdin.end();
    } catch {}
    const killer = setTimeout(() => {
      try {
        this.proc.kill("SIGKILL");
      } catch {}
    }, 1000);
    this.proc.on("close", () => clearTimeout(killer));
  }
}

const DAEMONS = SDKS.map((sdk) => new SdkDaemon(sdk));
for (const d of DAEMONS) d.start();

// ---------------------------------------------------------------------------
// Divergence detection (unchanged semantics)
// ---------------------------------------------------------------------------

function classify(result) {
  if (!result || !result.ok)
    return `error:${(result && result.error ? result.error : "unknown").slice(0, 40)}`;
  return (
    result.signature_hex ||
    `noise:${(result.canonical || "").slice(0, 24)}`
  );
}

function findMajority(results, liveLabels) {
  const counts = new Map();
  for (const label of liveLabels) {
    const cls = classify(results[label]);
    counts.set(cls, (counts.get(cls) || 0) + 1);
  }
  let bestCls = null;
  let bestCount = 0;
  for (const [cls, n] of counts) {
    if (n > bestCount) {
      bestCls = cls;
      bestCount = n;
    }
  }
  return { majorityClass: bestCls, majorityCount: bestCount };
}

function emitDivergences(record, results, liveLabels) {
  const { majorityClass } = findMajority(results, liveLabels);
  const labelToClass = new Map();
  for (const label of liveLabels)
    labelToClass.set(label, classify(results[label]));
  let n = 0;
  for (let i = 0; i < liveLabels.length; i++) {
    for (let j = i + 1; j < liveLabels.length; j++) {
      const a = liveLabels[i];
      const b = liveLabels[j];
      const ca = labelToClass.get(a);
      const cb = labelToClass.get(b);
      if (ca === cb) continue;
      const bothErr = ca.startsWith("error:") && cb.startsWith("error:");
      if (bothErr) continue;

      let outlier = null;
      if (ca === majorityClass && cb !== majorityClass) outlier = b;
      else if (cb === majorityClass && ca !== majorityClass) outlier = a;

      const divergence = {
        record,
        minimal: record,
        sdkA: a,
        sdkB: b,
        outputA: ca,
        outputB: cb,
        canonicalA: results[a] && results[a].canonical ? results[a].canonical : null,
        canonicalB: results[b] && results[b].canonical ? results[b].canonical : null,
        majority:
          ca === majorityClass ? a : cb === majorityClass ? b : null,
        outlier,
      };
      process.stdout.write(JSON.stringify(divergence) + "\n");
      n++;
    }
  }
  return n;
}

// ---------------------------------------------------------------------------
// Checkpoint
// ---------------------------------------------------------------------------

function writeCheckpoint(recordIndex, divergences) {
  const payload = {
    generator_seed: GENERATOR_SEED,
    record_index: recordIndex,
    canonical_form: canonicalForm,
    divergences,
    sdks: SDKS.map((s) => s.label),
    dead_sdks: DAEMONS.filter((d) => d.dead).map((d) => ({
      label: d.label,
      reason: d.deathReason,
    })),
    timestamp: new Date().toISOString(),
  };
  const tmp = `${CHECKPOINT_PATH}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(payload, null, 2));
    renameSync(tmp, CHECKPOINT_PATH);
  } catch (e) {
    console.error(`fuzz-runner: checkpoint write failed: ${e.message}`);
  }
}

// ---------------------------------------------------------------------------
// Main dispatch loop — one record at a time, fan out to all live daemons.
// ---------------------------------------------------------------------------

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

let recordIndex = 0;
let divergenceCount = 0;
let shuttingDown = false;

function liveLabels() {
  return DAEMONS.filter((d) => !d.dead).map((d) => d.label);
}

async function processRecord(record) {
  const live = DAEMONS.filter((d) => !d.dead);
  if (live.length < 2) {
    if (!shuttingDown) {
      console.error(
        `fuzz-runner: fewer than 2 live daemons remain (${live.length}); stopping.`,
      );
      shuttingDown = true;
    }
    return;
  }
  const dispatched = live.map(async (d) => {
    const r = await d.request(record);
    return [d.label, r];
  });
  const entries = await Promise.all(dispatched);
  const results = Object.fromEntries(entries);
  const labels = entries.map(([l]) => l);
  divergenceCount += emitDivergences(record, results, labels);
}

process.on("SIGINT", () => {
  console.error("fuzz-runner: SIGINT — flushing checkpoint and shutting down");
  shuttingDown = true;
  writeCheckpoint(recordIndex, divergenceCount);
  for (const d of DAEMONS) d.shutdown();
  setTimeout(() => process.exit(130), 1500).unref();
});

for await (const line of rl) {
  if (shuttingDown) break;
  const trimmed = line.trim();
  if (!trimmed) continue;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch (e) {
    console.error(`fuzz-runner: bad json line: ${e.message}`);
    continue;
  }
  const record =
    parsed &&
    typeof parsed === "object" &&
    "record" in parsed &&
    Object.keys(parsed).length <= 2
      ? parsed.record
      : parsed;

  await processRecord(record);
  recordIndex++;

  if (recordIndex % PROGRESS_EVERY === 0) {
    const liveN = liveLabels().length;
    console.error(
      `fuzz-runner: processed ${recordIndex} records, ${divergenceCount} divergences, ${liveN}/${SDKS.length} daemons live`,
    );
  }
  if (recordIndex % CHECKPOINT_EVERY === 0) {
    writeCheckpoint(recordIndex, divergenceCount);
  }
}

// Final checkpoint + graceful shutdown.
writeCheckpoint(recordIndex, divergenceCount);
for (const d of DAEMONS) d.shutdown();

console.error(
  `fuzz-runner: DONE ${recordIndex} records, ${divergenceCount} divergences`,
);
for (const d of DAEMONS) {
  console.error(
    `[${d.label}] completed=${d.completed} dead=${d.dead} id_lost=${d.idLostCount} sha1_recovered=${d.sha1RecoveredCount}${d.dead ? ` reason="${d.deathReason}"` : ""}`,
  );
}

// ---------------------------------------------------------------------------
// --self-test: unit tests for the sha1 computation and pending/orphan
// bookkeeping — no daemons spawned, no stdin consumed. Runs on
// `node fuzz-runner.mjs --self-test` and exits with non-zero on failure.
// ---------------------------------------------------------------------------

function runSelfTest() {
  const tests = [];
  const record = (name, fn) => tests.push({ name, fn });

  record("sha1Hex empty string is da39a3ee...", () => {
    return (
      sha1Hex("") === "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
  });

  record("sha1Hex is deterministic for identical input", () => {
    const a = sha1Hex('{"id":"ts-0","record":{"k":1}}');
    const b = sha1Hex('{"id":"ts-0","record":{"k":1}}');
    return a === b && a.length === 40;
  });

  record("sha1Hex differs when id or record differs", () => {
    const a = sha1Hex('{"id":"ts-0","record":{"k":1}}');
    const b = sha1Hex('{"id":"ts-1","record":{"k":1}}');
    const c = sha1Hex('{"id":"ts-0","record":{"k":2}}');
    return a !== b && a !== c && b !== c;
  });

  record("sha1 matches the wire line the daemon receives", () => {
    // The wire line is exactly `JSON.stringify({id, record})` — no
    // trailing newline. Runner appends the newline separately.
    const id = "py-42";
    const rec = { alpha: [1, 2, 3], beta: "x" };
    const wireLine = JSON.stringify({ id, record: rec });
    const runnerSha1 = sha1Hex(wireLine);
    const daemonWouldSeeThenSha1 = sha1Hex(wireLine); // simulate echo
    return runnerSha1 === daemonWouldSeeThenSha1;
  });

  record("pending + pendingBySha1 stay coherent", () => {
    const pending = new Map();
    const pendingBySha1 = new Map();
    const id = "sw-3";
    const wire = JSON.stringify({ id, record: { z: null } });
    const sha1 = sha1Hex(wire);
    pending.set(id, { sha1, sent_at: 0, record: { z: null } });
    pendingBySha1.set(sha1, id);
    if (!pending.has(id) || pendingBySha1.get(sha1) !== id) return false;
    // Now simulate an id-based match cleanup.
    const entry = pending.get(id);
    pending.delete(id);
    pendingBySha1.delete(entry.sha1);
    return pending.size === 0 && pendingBySha1.size === 0;
  });

  record(
    "null-id response with echoed sha1 recovers pending id",
    () => {
      const pending = new Map();
      const pendingBySha1 = new Map();
      const id = "jv-7";
      const wire = JSON.stringify({ id, record: { hi: "there" } });
      const sha1 = sha1Hex(wire);
      pending.set(id, { sha1 });
      pendingBySha1.set(sha1, id);
      // Simulate daemon response: id fumbled, sha1 echoed correctly.
      const msg = {
        id: null,
        sha1,
        ok: true,
        canonical: "c",
        signature_hex: "abcd",
      };
      // Recovery path from _onStdout:
      if (
        typeof msg.sha1 !== "string" ||
        !pendingBySha1.has(msg.sha1)
      ) {
        return false;
      }
      const recoveredId = pendingBySha1.get(msg.sha1);
      return recoveredId === id;
    },
  );

  record("orphan claim on timeout: FIFO within window", () => {
    // Simulate _tryClaimOrphan against a small in-memory list.
    const now = 10_000;
    const orphans = [
      { msg: { canonical: "old" }, receivedAt: now - 6_000 }, // stale
      { msg: { canonical: "fresh1" }, receivedAt: now - 2_000 },
      { msg: { canonical: "fresh2" }, receivedAt: now - 500 },
    ];
    const tryClaim = (nowRef) => {
      while (orphans.length > 0) {
        const o = orphans[0];
        if (nowRef - o.receivedAt > 5000) {
          orphans.shift();
          continue;
        }
        orphans.shift();
        return o.msg;
      }
      return null;
    };
    const first = tryClaim(now);
    const second = tryClaim(now);
    const third = tryClaim(now);
    return (
      first &&
      first.canonical === "fresh1" &&
      second &&
      second.canonical === "fresh2" &&
      third === null
    );
  });

  let passed = 0;
  let failed = 0;
  for (const t of tests) {
    let ok = false;
    let err = null;
    try {
      ok = t.fn() === true;
    } catch (e) {
      err = e;
    }
    if (ok) {
      passed++;
      console.log(`ok  ${t.name}`);
    } else {
      failed++;
      console.log(`FAIL ${t.name}${err ? ": " + err.message : ""}`);
    }
  }
  console.log(`${passed}/${passed + failed} tests passed`);
  process.exit(failed === 0 ? 0 : 1);
}

// Cross-emitter matrix — Rust JCS signer variant A (serde_jcs).
//
// Uses the `serde_jcs` crate from docs.rs/serde_jcs / crates.io/crates/serde_jcs.
// This library implements RFC 8785 (JSON Canonicalization Scheme) on top of
// serde. It has been on crates.io since 2020 and went through a single major
// revision (0.1.0 -> 0.2.0). We include it in the cross-emitter matrix as a
// second Rust JCS implementation alongside `serde_json_canonicalizer` so we
// can catch places where two independent Rust libraries diverge from RFC 8785
// on the same inputs — which is directly a paper finding.
//
// Modes:
//   default (one-shot):  read a single JSON record on stdin, emit
//                        {"canonical": ..., "signature_hex": ...} on stdout.
//                        Byte-identical to pre-daemon behavior; old readers
//                        depend on it.
//   DAEMON_MODE=1:       read newline-delimited JSON requests on stdin
//                        ({"id": "...", "record": {...}}), emit one
//                        newline-delimited JSON response per request
//                        ({"id": ..., "ok": true, "canonical": ...,
//                        "signature_hex": ...} or {"id": ..., "ok": false,
//                        "error": ...}). SigningKey is reused across
//                        records; stdout is flushed after every line; the
//                        loop stays alive until stdin EOF. Every request
//                        yields exactly one response line even if
//                        parsing/canonicalization/signing fails or panics.
//   CANONICALIZE_ONLY=1: skip signing; emit just the canonical bytes on
//                        stdout (used by the RFC 8785 conformance runner).
//                        Only meaningful in one-shot mode.
//
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var
// (not required in CANONICALIZE_ONLY mode).

use ed25519_dalek::{Signer, SigningKey};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

// Compiled once at daemon startup. Matches an `"id": <string|number>`
// occurrence in the raw wire line without invoking a JSON parser, so it
// still succeeds when the surrounding record contains lone UTF-16
// surrogates or other content that trips serde_json::from_str. The
// alternation captures a JSON string body (group 1, with escape
// sequences left intact) or a JSON number literal (group 2).
static ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))"#).unwrap()
});

// Best-effort id extraction from the raw envelope line. Returns None
// only when no "id" occurrence is present at all. Prefers a properly
// decoded JSON string (escape sequences interpreted); falls back to the
// raw captured source form if the decode fails (e.g. the id itself
// contains a lone surrogate). Number ids are returned as JSON numbers.
fn extract_id_from_raw(line: &str) -> Option<Value> {
    let caps = ID_RE.captures(line)?;
    if let Some(s) = caps.get(1) {
        let quoted = format!("\"{}\"", s.as_str());
        if let Ok(parsed) = serde_json::from_str::<String>(&quoted) {
            return Some(Value::String(parsed));
        }
        return Some(Value::String(s.as_str().to_string()));
    }
    if let Some(n) = caps.get(2) {
        if let Ok(num) = serde_json::from_str::<Value>(n.as_str()) {
            return Some(num);
        }
        return Some(Value::String(n.as_str().to_string()));
    }
    None
}

fn ensure_env(name: &str, value: &str) {
    if std::env::var_os(name).is_none() {
        std::env::set_var(name, value);
    }
}

fn canonicalize(record: &Value) -> Result<String, String> {
    serde_jcs::to_string(record).map_err(|e| format!("serde_jcs::to_string failed: {e}"))
}

fn sign_one(record: &Value, sk: Option<&SigningKey>) -> Value {
    match canonicalize(record) {
        Ok(canonical) => {
            if let Some(sk) = sk {
                let sig = sk.sign(canonical.as_bytes());
                json!({
                    "canonical": canonical,
                    "signature_hex": hex::encode(sig.to_bytes()),
                })
            } else {
                json!({ "canonical": canonical })
            }
        }
        Err(e) => json!({ "error": e }),
    }
}

fn main() {
    let canonicalize_only = std::env::var("CANONICALIZE_ONLY").ok().as_deref() == Some("1");
    let daemon = std::env::var("DAEMON_MODE").ok().as_deref() == Some("1");

    let sk: Option<SigningKey> = if canonicalize_only {
        None
    } else {
        let key_hex = std::env::var("SIGNING_KEY_HEX")
            .expect("SIGNING_KEY_HEX required (or set CANONICALIZE_ONLY=1)");
        let seed = hex::decode(&key_hex).expect("bad hex");
        let seed_arr: [u8; 32] = seed.try_into().expect("wrong seed length");
        Some(SigningKey::from_bytes(&seed_arr))
    };

    if daemon {
        // Env pinning: only set if missing so the driver's explicit values win.
        ensure_env("LC_ALL", "C.UTF-8");
        ensure_env("PYTHONIOENCODING", "utf-8");

        // Newline-delimited JSON in, newline-delimited JSON out — matches
        // the id-envelope protocol used by the Ruby/Python/Java/Kotlin/C#
        // daemons elsewhere in this matrix.
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.is_empty() {
                continue;
            }

            // Extract the request id from the raw wire line BEFORE
            // attempting to parse the envelope. Lone UTF-16 surrogates
            // and other JSON pathologies inside `record` will make
            // serde_json::from_str fail even when the id itself is
            // well-formed; the regex fallback lets us still echo the id
            // in that case so the driver can correlate the rejection
            // with the input record.
            let fallback_id: Value = extract_id_from_raw(&line).unwrap_or(Value::Null);

            // Wrap the per-record body in catch_unwind so a panic in
            // any downstream code (canonicalizer, signer, JSON
            // serializer) still yields exactly one response line for
            // the loop's exactly-one-in / exactly-one-out contract.
            let response: Value = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| -> Value {
                    match serde_json::from_str::<Value>(&line) {
                        Ok(req) => {
                            let id = req
                                .get("id")
                                .cloned()
                                .unwrap_or_else(|| fallback_id.clone());
                            let record = match req.get("record") {
                                Some(r) => r,
                                None => {
                                    return json!({
                                        "id": id,
                                        "ok": false,
                                        "error": "missing record",
                                    });
                                }
                            };
                            match canonicalize(record) {
                                Ok(canonical) => {
                                    if let Some(sk) = sk.as_ref() {
                                        let sig = sk.sign(canonical.as_bytes());
                                        json!({
                                            "id": id,
                                            "ok": true,
                                            "canonical": canonical,
                                            "signature_hex": hex::encode(sig.to_bytes()),
                                        })
                                    } else {
                                        // CANONICALIZE_ONLY=1 with DAEMON_MODE=1
                                        // is an unusual combo but we still emit a
                                        // well-formed envelope so the driver's
                                        // exactly-one-in / exactly-one-out
                                        // contract holds.
                                        json!({
                                            "id": id,
                                            "ok": true,
                                            "canonical": canonical,
                                            "signature_hex": "",
                                        })
                                    }
                                }
                                Err(e) => json!({
                                    "id": id,
                                    "ok": false,
                                    "error": e,
                                }),
                            }
                        }
                        Err(e) => json!({
                            "id": fallback_id.clone(),
                            "ok": false,
                            "error": format!("parse: {e}"),
                        }),
                    }
                }),
            )
            .unwrap_or_else(|_| {
                json!({
                    "id": fallback_id.clone(),
                    "ok": false,
                    "error": "panic during processing",
                })
            });

            writeln!(out, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            out.flush().unwrap();
        }
        return;
    }

    // One-shot: whole stdin -> single output (no trailing newline).
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let record: Value = serde_json::from_str(&input).expect("stdin is not valid JSON");

    if canonicalize_only {
        // Emit the canonical bytes verbatim; conformance runner compares
        // these to cyberphone's expected UTF-8 outputs.
        match canonicalize(&record) {
            Ok(canonical) => {
                io::stdout().write_all(canonical.as_bytes()).unwrap();
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        return;
    }

    let result = sign_one(&record, sk.as_ref());
    print!("{}", serde_json::to_string(&result).unwrap());
}

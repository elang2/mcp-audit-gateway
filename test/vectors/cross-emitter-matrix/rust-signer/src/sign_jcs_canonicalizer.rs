// Cross-emitter matrix — Rust JCS signer variant B (serde_json_canonicalizer).
//
// Uses the `serde_json_canonicalizer` crate
// (crates.io/crates/serde_json_canonicalizer). This library implements
// RFC 8785 (JSON Canonicalization Scheme) directly on top of serde_json's
// Value model. It is more actively maintained than `serde_jcs` (more
// versions, more recent bug fixes) and is the crate recommended by the
// cyberphone/json-canonicalization README as the modern Rust
// implementation.
//
// Modes and env-var conventions are identical to sign_jcs_serde_jcs.rs
// so both binaries are interchangeable inside the matrix runner. In
// DAEMON_MODE=1 both use the id-envelope wire protocol:
//   in:  {"id": "<opaque>", "record": <object>}
//   out: {"id": "<same>", "ok": true,  "canonical": "<str>", "signature_hex": "<hex>"}
//     or {"id": "<same>", "ok": false, "error": "<short>"}

use ed25519_dalek::{Signer, SigningKey};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

// Compiled once at daemon startup. Matches an `"id": <string|number>`
// occurrence in the raw wire line without invoking a JSON parser, so it
// still succeeds when the surrounding record contains lone UTF-16
// surrogates or other content that trips serde_json::from_str.
static ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))"#).unwrap()
});

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
    serde_json_canonicalizer::to_string(record)
        .map_err(|e| format!("serde_json_canonicalizer::to_string failed: {e}"))
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
        ensure_env("LC_ALL", "C.UTF-8");
        ensure_env("PYTHONIOENCODING", "utf-8");

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

            let fallback_id: Value = extract_id_from_raw(&line).unwrap_or(Value::Null);

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

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let record: Value = serde_json::from_str(&input).expect("stdin is not valid JSON");

    if canonicalize_only {
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

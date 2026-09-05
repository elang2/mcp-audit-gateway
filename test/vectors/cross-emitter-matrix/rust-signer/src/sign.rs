// Cross-emitter matrix — Rust signer.
// Uses tuple-array canonical form matching ../verify.mjs etc.
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
//
// Modes:
//   default (one-shot):  read a single JSON record on stdin, emit
//                        {"canonical": ..., "signature_hex": ...} on stdout
//                        with no trailing newline. Byte-identical to the
//                        pre-daemon behavior; old readers depend on it.
//                        On canonicalize error, prints the error to stderr
//                        and exits non-zero.
//   DAEMON_MODE=1:       read newline-delimited JSON requests on stdin
//                        ({"id": "...", "record": {...}}), emit one
//                        newline-delimited JSON response per request
//                        ({"id": ..., "ok": true, "canonical": ...,
//                        "signature_hex": ...} or {"id": ..., "ok": false,
//                        "error": ...}). SigningKey is reused across
//                        records; stdout is flushed after every line; the
//                        loop stays alive until stdin EOF. Rejections
//                        (unsafe integers, floats, non-object records)
//                        surface as ok:false envelopes — the daemon does
//                        NOT catch-and-hide them; the rejection map is the
//                        paper's scientific signal.
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

const FIELD_ORDER: &[&str] = &[
    "id","timestamp","method","toolName","namespace","upstream",
    "principal","durationMs","success","errorCode","previousHash",
];

// JS Number.MAX_SAFE_INTEGER == 2^53 - 1.
const SAFE_INT_MAX: i64 = (1_i64 << 53) - 1;

#[derive(Debug)]
enum CanonError {
    NotObject,
    UnsafeInteger(i64),
    UnsafeUnsigned(u64),
    UnsafeFloat(f64),
    UnsafeType(String),
    Serialize(String),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonError::NotObject => write!(f, "record is not a JSON object"),
            CanonError::UnsafeInteger(i) => write!(f, "unsafe integer: {}", i),
            CanonError::UnsafeUnsigned(u) => write!(f, "unsafe integer: {}", u),
            CanonError::UnsafeFloat(v) => write!(f, "unsafe number (float): {}", v),
            CanonError::UnsafeType(t) => write!(f, "unsafe type: {}", t),
            CanonError::Serialize(e) => write!(f, "serialize canonical failed: {}", e),
        }
    }
}

impl std::error::Error for CanonError {}

fn utf16_be_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

fn canonicalize_value(v: &Value) -> Result<Value, CanonError> {
    match v {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::String(s) => Ok(Value::String(s.clone())),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i > SAFE_INT_MAX || i < -SAFE_INT_MAX {
                    return Err(CanonError::UnsafeInteger(i));
                }
                Ok(Value::Number(i.into()))
            } else if let Some(u) = n.as_u64() {
                // u64 that does not fit in i64 is by construction > 2^63,
                // which is far outside the JS safe-integer range.
                Err(CanonError::UnsafeUnsigned(u))
            } else if let Some(f) = n.as_f64() {
                Err(CanonError::UnsafeFloat(f))
            } else {
                Err(CanonError::UnsafeType("unknown number kind".to_string()))
            }
        }
        Value::Array(arr) => {
            let inner: Result<Vec<Value>, CanonError> =
                arr.iter().map(canonicalize_value).collect();
            Ok(Value::Array(vec![Value::String("L".into()), Value::Array(inner?)]))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_be_bytes(a).cmp(&utf16_be_bytes(b)));
            let pairs: Result<Vec<Value>, CanonError> = keys.iter().map(|k| {
                canonicalize_value(&map[*k]).map(|cv| {
                    Value::Array(vec![Value::String((*k).clone()), cv])
                })
            }).collect();
            Ok(Value::Array(vec![Value::String("M".into()), Value::Array(pairs?)]))
        }
    }
}

fn canonicalize(record: &Value) -> Result<String, CanonError> {
    let obj = record.as_object().ok_or(CanonError::NotObject)?;
    let mut ordered: Vec<Value> = Vec::with_capacity(FIELD_ORDER.len() + 4);
    for k in FIELD_ORDER {
        let v = obj.get(*k).cloned().unwrap_or(Value::Null);
        ordered.push(Value::Array(vec![
            Value::String(k.to_string()),
            canonicalize_value(&v)?,
        ]));
    }
    for opt in &["decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"] {
        if let Some(v) = obj.get(*opt) {
            if !v.is_null() {
                ordered.push(Value::Array(vec![
                    Value::String(opt.to_string()),
                    canonicalize_value(v)?,
                ]));
            }
        }
    }
    serde_json::to_string(&Value::Array(ordered))
        .map_err(|e| CanonError::Serialize(e.to_string()))
}

fn ensure_env(name: &str, value: &str) {
    if std::env::var_os(name).is_none() {
        std::env::set_var(name, value);
    }
}

fn sign_record(record: &Value, sk: &SigningKey) -> Result<(String, String), String> {
    let canonical = canonicalize(record).map_err(|e| e.to_string())?;
    let sig = sk.sign(canonical.as_bytes());
    Ok((canonical, hex::encode(sig.to_bytes())))
}

fn main() {
    let daemon = std::env::var("DAEMON_MODE").ok().as_deref() == Some("1");

    let key_hex = std::env::var("SIGNING_KEY_HEX").expect("SIGNING_KEY_HEX required");
    let seed = hex::decode(&key_hex).expect("bad hex");
    let seed_arr: [u8; 32] = seed.try_into().expect("wrong seed length");
    let sk = SigningKey::from_bytes(&seed_arr);

    if daemon {
        // Env pinning: only set if missing so the driver's explicit values win.
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

            // Extract the request id from the raw wire line BEFORE
            // attempting to parse the envelope. Lone UTF-16 surrogates
            // and other JSON pathologies inside `record` will make
            // serde_json::from_str fail even when the id itself is
            // perfectly well-formed; the regex fallback lets us still
            // echo the id in that case so the driver can correlate the
            // rejection with the input record. Rejection is signal.
            let fallback_id: Value = extract_id_from_raw(&line).unwrap_or(Value::Null);

            // Wrap the per-record body in catch_unwind so a panic in
            // any downstream code (canonicalizer, signer, JSON
            // serializer) still yields exactly one response line for
            // the loop's exactly-one-in / exactly-one-out contract.
            // The Result-based path from the previous iteration is
            // preserved; catch_unwind is belt-and-suspenders.
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
                            match sign_record(record, &sk) {
                                Ok((canonical, sig_hex)) => json!({
                                    "id": id,
                                    "ok": true,
                                    "canonical": canonical,
                                    "signature_hex": sig_hex,
                                }),
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

    // One-shot: byte-identical to pre-patch behavior on success.
    // On canonicalize error, print to stderr and exit non-zero.
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let record: Value = serde_json::from_str(&input).unwrap();

    let canonical = match canonicalize(&record) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("canonicalize failed: {}", e);
            std::process::exit(1);
        }
    };
    let sig = sk.sign(canonical.as_bytes());
    let out = json!({
        "canonical": canonical,
        "signature_hex": hex::encode(sig.to_bytes()),
    });
    print!("{}", serde_json::to_string(&out).unwrap());
}

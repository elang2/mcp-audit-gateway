// Cross-emitter matrix — Rust verifier.
//
// Modes:
//   default (one-shot):  read a single JSON payload
//                        {"record": ..., "signature_hex": ...,
//                         "public_key_hex": ...} on stdin, emit
//                        {"verified": bool, "local_canonical": ...,
//                         "sig_hex": ...} on stdout with no trailing
//                        newline. Byte-identical to pre-daemon behavior
//                        on success. On canonicalize error, prints the
//                        error to stderr and exits non-zero.
//   DAEMON_MODE=1:       read newline-delimited JSON requests on stdin
//                        ({"id": "...", "record": {...}}), emit one
//                        newline-delimited JSON response per request.
//                        The public key is provided once at startup via
//                        the PUBLIC_KEY_HEX and SIGNATURE_HEX env vars,
//                        or per-record inside the request object as
//                        {"public_key_hex": ..., "signature_hex": ...}.
//                        VerifyingKey is cached across records when the
//                        pubkey does not change. Loop stays alive until
//                        stdin EOF; per-record errors continue the loop.
//                        Rejections surface as ok:false envelopes — the
//                        daemon does NOT catch-and-hide them.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

// See sign.rs for the rationale — regex extractor for the request id
// that runs against the raw wire line so we still emit a correlated
// response when the envelope contains content that trips
// serde_json::from_str (e.g. lone UTF-16 surrogates in the record).
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

fn decode_pubkey(pub_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(pub_hex).map_err(|e| format!("bad public_key_hex: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "public_key_hex wrong length".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("VerifyingKey::from_bytes: {e}"))
}

fn decode_sig(sig_hex: &str) -> Result<Signature, String> {
    let bytes = hex::decode(sig_hex).map_err(|e| format!("bad signature_hex: {e}"))?;
    let arr: [u8; 64] = bytes.try_into().map_err(|_| "signature_hex wrong length".to_string())?;
    Ok(Signature::from_bytes(&arr))
}

fn verify_one(record: &Value, vk: &VerifyingKey, sig: &Signature) -> Result<(bool, String), String> {
    let canonical = canonicalize(record).map_err(|e| e.to_string())?;
    let verified = vk.verify(canonical.as_bytes(), sig).is_ok();
    Ok((verified, canonical))
}

fn main() {
    let daemon = std::env::var("DAEMON_MODE").ok().as_deref() == Some("1");

    if daemon {
        ensure_env("LC_ALL", "C.UTF-8");
        ensure_env("PYTHONIOENCODING", "utf-8");

        // Optional startup pubkey/signature — reused across records when
        // requests omit them. This is the whole point of daemon mode.
        let mut cached_vk: Option<(String, VerifyingKey)> = None;
        if let Ok(h) = std::env::var("PUBLIC_KEY_HEX") {
            if let Ok(vk) = decode_pubkey(&h) {
                cached_vk = Some((h, vk));
            }
        }
        let default_sig_hex: Option<String> = std::env::var("SIGNATURE_HEX").ok();

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

            // Extract id from the raw wire line first — see sign.rs.
            let fallback_id: Value = extract_id_from_raw(&line).unwrap_or(Value::Null);

            // Compute the response inside catch_unwind so panics
            // still produce exactly one output line for the loop's
            // exactly-one-in / exactly-one-out contract. The Result
            // path is preserved; catch_unwind is belt-and-suspenders.
            // cached_vk is mutated through &mut inside the closure —
            // AssertUnwindSafe accepts the borrow because we do not
            // observe partially-updated cache state on the panic path.
            let cached_vk_ref = &mut cached_vk;
            let default_sig_hex_ref = &default_sig_hex;
            let response: Value = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| -> Value {
                    match serde_json::from_str::<Value>(&line) {
                        Ok(req) => {
                            let id = req
                                .get("id")
                                .cloned()
                                .unwrap_or_else(|| fallback_id.clone());

                            // Resolve pubkey: request > cache/env.
                            let pubkey_result: Result<&VerifyingKey, String> = match req
                                .get("public_key_hex")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                            {
                                Some(h) => {
                                    if cached_vk_ref.as_ref().map(|(k, _)| k.as_str())
                                        != Some(h.as_str())
                                    {
                                        match decode_pubkey(&h) {
                                            Ok(vk) => *cached_vk_ref = Some((h, vk)),
                                            Err(e) => {
                                                return json!({
                                                    "id": id,
                                                    "ok": false,
                                                    "error": e,
                                                });
                                            }
                                        }
                                    }
                                    Ok(&cached_vk_ref.as_ref().unwrap().1)
                                }
                                None => match cached_vk_ref.as_ref() {
                                    Some((_, vk)) => Ok(vk),
                                    None => Err(
                                        "missing public_key_hex (no cached key)".to_string(),
                                    ),
                                },
                            };
                            let vk = match pubkey_result {
                                Ok(vk) => vk,
                                Err(e) => {
                                    return json!({"id": id, "ok": false, "error": e});
                                }
                            };

                            // Resolve signature: request > default env.
                            let sig_hex_opt = req
                                .get("signature_hex")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                                .or_else(|| default_sig_hex_ref.clone());
                            let sig_hex = match sig_hex_opt {
                                Some(s) => s,
                                None => {
                                    return json!({
                                        "id": id,
                                        "ok": false,
                                        "error": "missing signature_hex",
                                    });
                                }
                            };
                            let sig = match decode_sig(&sig_hex) {
                                Ok(s) => s,
                                Err(e) => {
                                    return json!({"id": id, "ok": false, "error": e});
                                }
                            };

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
                            match verify_one(record, vk, &sig) {
                                Ok((verified, canonical)) => json!({
                                    "id": id,
                                    "ok": true,
                                    "canonical": canonical,
                                    "signature_hex": sig_hex,
                                    "verified": verified,
                                }),
                                Err(e) => json!({"id": id, "ok": false, "error": e}),
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
    let payload: Value = serde_json::from_str(&input).unwrap();
    let record = &payload["record"];
    let sig_hex = payload["signature_hex"].as_str().unwrap();
    let pub_hex = payload["public_key_hex"].as_str().unwrap();

    let pub_bytes: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes);

    let canonical = match canonicalize(record) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("canonicalize failed: {}", e);
            std::process::exit(1);
        }
    };
    let verified = vk.verify(canonical.as_bytes(), &sig).is_ok();

    let out = json!({
        "verified": verified,
        "local_canonical": canonical,
        "sig_hex": sig_hex,
    });
    print!("{}", serde_json::to_string(&out).unwrap());
}

// Cross-emitter matrix — Java signer, JCS variant.
// Uses the cyberphone RFC 8785 reference implementation
// (io.github.erdtman:java-json-canonicalization:1.1 from Maven Central,
// vendored at ../runners/java-json-canonicalization-1.1.jar).
//
// This variant signs the *JCS canonical form* of the record as-is
// (no tuple-array wrapping, no fixed field order, no type-tags),
// so the byte sequence fed to Ed25519 is exactly the RFC 8785
// canonical serialization. Byte-for-byte matches cyberphone's own
// testdata/output/*.json for the corresponding input.
//
// -----------------------------------------------------------------------
// Daemon protocol (must match the wire contract in fuzzing/fuzz-runner.mjs):
// -----------------------------------------------------------------------
//   Startup env: DAEMON_MODE=1
//                SIGNING_KEY_HEX=<64 hex chars>
//
//   Request  (one NDJSON line per record on stdin):
//       {"id": "<opaque-string>", "record": <object>}
//
//   Response (one NDJSON line per request on stdout, flushed):
//       {"id": "<same-id>", "ok": true,  "canonical": "<str>", "signature_hex": "<hex>"}
//     — or —
//       {"id": "<same-id>", "ok": false, "error": "<short-string>"}
//
// One-shot mode (DAEMON_MODE unset): reads a single record on stdin, writes
// a single JSON object (canonical + signature_hex) to stdout — byte-identical
// to the pre-daemon output. Preserved for direct/legacy invocations.
//
// Build+run:
//   JCS_CP=../runners/java-json-canonicalization-1.1.jar
//   javac -cp "$JCS_CP" SignJcs.java
//   SIGNING_KEY_HEX=... java -cp "$JCS_CP:." SignJcs   # one-shot, JSON on stdin
//   SIGNING_KEY_HEX=... DAEMON_MODE=1 java -cp "$JCS_CP:." SignJcs   # daemon

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SignJcs {

    // Regex fallback for id extraction from raw envelope line. Used when
    // parseEnvelope fails (e.g., pathological UTF-16 in the record breaks
    // our substring scan) so response id-correlation is preserved even on
    // rejection. Matches the wire-protocol regex used by the other daemons.
    static final Pattern ID_REGEX = Pattern.compile(
        "\"id\"\\s*:\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(-?\\d+(?:\\.\\d+)?))"
    );

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    // Minimal JSON string escape sufficient for the {"canonical":...} envelope.
    // The canonical form is JCS-clean already; we only need to re-embed it as
    // a JSON string value.
    static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    static boolean isWs(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    // Scan a JSON string starting at s[start] (which must be '"'); return the
    // index one past the closing quote. Handles backslash escapes but does
    // not validate the string contents (we're extracting, not parsing).
    static int scanStringEnd(String s, int start) {
        int i = start + 1;
        int len = s.length();
        while (i < len) {
            char c = s.charAt(i);
            if (c == '\\') { i += 2; continue; }
            if (c == '"') return i + 1;
            i++;
        }
        throw new RuntimeException("unterminated string");
    }

    // Scan a JSON object or array starting at s[start]; return the index one
    // past the matching close bracket. Respects string boundaries so that
    // brackets inside strings don't affect depth.
    static int scanBracketEnd(String s, int start) {
        char open = s.charAt(start);
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        int i = start;
        int len = s.length();
        while (i < len) {
            char c = s.charAt(i);
            if (c == '"') { i = scanStringEnd(s, i); continue; }
            if (c == open) depth++;
            else if (c == close) { depth--; if (depth == 0) return i + 1; }
            i++;
        }
        throw new RuntimeException("unterminated bracket");
    }

    // Scan a JSON value starting at s[start] (after skipping leading
    // whitespace); return the index one past the value.
    static int scanValueEnd(String s, int start) {
        int i = start;
        int len = s.length();
        while (i < len && isWs(s.charAt(i))) i++;
        if (i >= len) throw new RuntimeException("EOF in value");
        char c = s.charAt(i);
        if (c == '"') return scanStringEnd(s, i);
        if (c == '{' || c == '[') return scanBracketEnd(s, i);
        int j = i;
        while (j < len) {
            char cc = s.charAt(j);
            if (cc == ',' || cc == '}' || cc == ']' || isWs(cc)) break;
            j++;
        }
        return j;
    }

    // Decode a JSON string literal (with surrounding quotes) into its plain
    // text form. Used only for matching envelope keys ("id"/"record"),
    // so we tolerate any escape by falling back to the literal char.
    static String jsonUnescape(String raw) {
        if (raw.length() < 2 || raw.charAt(0) != '"') return raw;
        StringBuilder sb = new StringBuilder(raw.length() - 2);
        int i = 1;
        int end = raw.length() - 1;
        while (i < end) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < end) {
                char nxt = raw.charAt(i + 1);
                switch (nxt) {
                    case '"':  sb.append('"');  i += 2; break;
                    case '\\': sb.append('\\'); i += 2; break;
                    case '/':  sb.append('/');  i += 2; break;
                    case 'n':  sb.append('\n'); i += 2; break;
                    case 'r':  sb.append('\r'); i += 2; break;
                    case 't':  sb.append('\t'); i += 2; break;
                    case 'b':  sb.append('\b'); i += 2; break;
                    case 'f':  sb.append('\f'); i += 2; break;
                    case 'u':
                        if (i + 6 <= end) {
                            try {
                                int cp = Integer.parseInt(raw.substring(i + 2, i + 6), 16);
                                sb.append((char) cp);
                                i += 6;
                            } catch (NumberFormatException nfe) {
                                sb.append(nxt); i += 2;
                            }
                        } else { sb.append(nxt); i += 2; }
                        break;
                    default: sb.append(nxt); i += 2;
                }
            } else { sb.append(c); i++; }
        }
        return sb.toString();
    }

    static class Envelope {
        String rawIdJson;      // raw JSON representation of "id" value (e.g. "\"t\"" or "42") — null if absent
        String rawRecordJson;  // raw JSON substring of "record" value — null if absent
    }

    // Extract raw "id" and "record" value substrings from an envelope line.
    // Uses only substring extraction (no object materialization) so it never
    // depends on the erdtman jar being present; JCS canonicalization happens
    // downstream via new JsonCanonicalizer(env.rawRecordJson).
    static Envelope parseEnvelope(String line) {
        Envelope env = new Envelope();
        int len = line.length();
        int i = 0;
        while (i < len && isWs(line.charAt(i))) i++;
        if (i >= len || line.charAt(i) != '{') throw new RuntimeException("envelope not object");
        i++;
        while (i < len) {
            while (i < len && (isWs(line.charAt(i)) || line.charAt(i) == ',')) i++;
            if (i >= len || line.charAt(i) == '}') break;
            if (line.charAt(i) != '"') throw new RuntimeException("expected key");
            int keyEnd = scanStringEnd(line, i);
            String key = jsonUnescape(line.substring(i, keyEnd));
            i = keyEnd;
            while (i < len && isWs(line.charAt(i))) i++;
            if (i >= len || line.charAt(i) != ':') throw new RuntimeException("expected colon");
            i++;
            int valStart = i;
            while (valStart < len && isWs(line.charAt(valStart))) valStart++;
            int valEnd = scanValueEnd(line, i);
            String rawVal = line.substring(valStart, valEnd);
            if (key.equals("id")) env.rawIdJson = rawVal;
            else if (key.equals("record")) env.rawRecordJson = rawVal;
            i = valEnd;
        }
        return env;
    }

    // Regex fallback for id extraction. Returns the id as its JSON
    // representation, or "null" if no id found. Used only when the primary
    // envelope parse fails and we still need an id to correlate the
    // rejection response with the request.
    static String extractIdJsonFallback(String line) {
        try {
            Matcher m = ID_REGEX.matcher(line);
            if (m.find()) {
                String s = m.group(1);
                if (s != null) return "\"" + s + "\"";
                String num = m.group(2);
                if (num != null) return num;
            }
        } catch (Throwable ignore) { /* fall through */ }
        return "null";
    }

    // JCS canonicalize the input record and sign; returns the raw response
    // body ({"canonical":...,"signature_hex":...}) — the id/ok wrapping is
    // added by the caller in daemon mode. One-shot mode uses this body
    // verbatim so pre-daemon output is byte-identical.
    static String signRecord(String recordJson, Signature sig, PrivateKey privKey) throws Exception {
        sig.initSign(privKey);
        // NOTE: JsonCanonicalizer reference lives inside this method so that
        // callers can catch NoClassDefFoundError on FIRST invocation and
        // surface "erdtman jar missing" per record rather than crashing.
        String canonical = new org.erdtman.jcs.JsonCanonicalizer(recordJson).getEncodedString();
        sig.update(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = sig.sign();
        return "{\"canonical\":" + jsonEscape(canonical)
             + ",\"signature_hex\":\"" + toHex(sigBytes) + "\"}";
    }

    public static void main(String[] args) throws Exception {
        String keyHex = System.getenv("SIGNING_KEY_HEX");
        if (keyHex == null || keyHex.isEmpty()) {
            System.err.println("SIGNING_KEY_HEX required");
            System.exit(1);
        }
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) Integer.parseInt(keyHex.substring(i * 2, i * 2 + 2), 16);
        }

        NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
        EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(paramSpec, seed);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        // Reuse a single Signature instance across records in daemon mode;
        // initSign() resets its internal state each call.
        Signature sig = Signature.getInstance("Ed25519");

        String daemon = System.getenv("DAEMON_MODE");
        boolean daemonMode = daemon != null && !daemon.isEmpty() && !daemon.equals("0");

        if (daemonMode) {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
            String line;
            while ((line = in.readLine()) != null) {
                if (line.isEmpty()) continue;
                // Paranoid outer try: guarantees exactly one response line
                // per input line, so the driver's response_count ==
                // request_count invariant holds under any failure mode.
                String response;
                String idJson = "null";
                try {
                    Envelope env;
                    try {
                        env = parseEnvelope(line);
                        if (env.rawIdJson != null) idJson = env.rawIdJson;
                    } catch (Throwable envErr) {
                        // Envelope parse failed — try the regex fallback for
                        // id so at least the rejection can be correlated.
                        idJson = extractIdJsonFallback(line);
                        throw envErr;
                    }
                    if (env.rawRecordJson == null) {
                        throw new RuntimeException("record field missing");
                    }
                    String body = signRecord(env.rawRecordJson, sig, privKey);
                    // body is {"canonical":...,"signature_hex":...} — splice
                    // id/ok in front by stripping the leading '{'.
                    response = "{\"id\":" + idJson + ",\"ok\":true," + body.substring(1);
                } catch (Throwable inner) {
                    // The erdtman jar is loaded lazily on the first
                    // JsonCanonicalizer reference; if it's missing at
                    // runtime we get NoClassDefFoundError (or a nested
                    // ClassNotFoundException). Normalize both to the
                    // "erdtman jar missing" error the driver expects.
                    String errMsg;
                    Throwable t = inner;
                    boolean jarMissing = false;
                    while (t != null) {
                        if (t instanceof NoClassDefFoundError || t instanceof ClassNotFoundException) {
                            String tm = t.getMessage();
                            if (tm != null && (tm.contains("org/erdtman") || tm.contains("org.erdtman"))) {
                                jarMissing = true; break;
                            }
                            // Any NoClassDefFoundError first-touched here is
                            // almost certainly the erdtman jar; be liberal.
                            jarMissing = true; break;
                        }
                        t = t.getCause();
                    }
                    if (jarMissing) {
                        errMsg = "erdtman jar missing";
                    } else {
                        errMsg = inner.getMessage() == null ? inner.getClass().getSimpleName() : inner.getMessage();
                    }
                    try {
                        response = "{\"id\":" + idJson + ",\"ok\":false,\"error\":" + jsonEscape(errMsg) + "}";
                    } catch (Throwable je) {
                        response = "{\"id\":" + idJson + ",\"ok\":false,\"error\":\"internal_encode_failure\"}";
                    }
                }
                out.println(response);
                out.flush();
            }
            return;
        }

        // One-shot mode: read all of stdin as one record. Byte-identical to
        // pre-daemon output (no id/ok wrapping).
        StringBuilder buf = new StringBuilder();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        char[] chunk = new char[4096];
        int n;
        while ((n = in.read(chunk)) != -1) buf.append(chunk, 0, n);
        System.out.print(signRecord(buf.toString(), sig, privKey));
    }
}

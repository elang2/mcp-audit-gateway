// Cross-emitter matrix — C# signer, JCS variant.
// Uses the cyberphone RFC 8785 reference implementation from NuGet
// (jsoncanonicalizer 1.0.0, namespace Org.Webpki.JsonCanonicalizer).
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
//   dotnet build -c Release SignJcs.csproj
//   SIGNING_KEY_HEX=... dotnet bin/Release/net9.0/SignJcs.dll   # one-shot
//   SIGNING_KEY_HEX=... DAEMON_MODE=1 dotnet bin/Release/net9.0/SignJcs.dll   # daemon
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using NSec.Cryptography;
using Org.Webpki.JsonCanonicalizer;

namespace McpMatrix {

public class SignJcsProgram {

    // Regex fallback for id extraction — matches the wire-protocol regex used
    // by the other daemons. Used when the primary envelope parse fails so
    // rejection responses can still be correlated with their request.
    static readonly Regex ID_REGEX = new Regex(
        "\"id\"\\s*:\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(-?\\d+(?:\\.\\d+)?))",
        RegexOptions.Compiled
    );

    // Minimal JSON string escape sufficient for the {"canonical":...} envelope.
    // The canonical form is JCS-clean already; we only need to re-embed it as
    // a JSON string value.
    static void JsonEscape(StringBuilder sb, string s) {
        sb.Append('"');
        foreach (char c in s) {
            switch (c) {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                case '\t': sb.Append("\\t");  break;
                case '\b': sb.Append("\\b");  break;
                case '\f': sb.Append("\\f");  break;
                default:
                    if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static bool IsWs(char c) => c == ' ' || c == '\t' || c == '\n' || c == '\r';

    // Scan a JSON string starting at s[start] (which must be '"'); return the
    // index one past the closing quote. Handles backslash escapes.
    static int ScanStringEnd(string s, int start) {
        int i = start + 1;
        int len = s.Length;
        while (i < len) {
            char c = s[i];
            if (c == '\\') { i += 2; continue; }
            if (c == '"') return i + 1;
            i++;
        }
        throw new Exception("unterminated string");
    }

    // Scan a JSON object or array starting at s[start]; return the index one
    // past the matching close bracket. Respects string boundaries.
    static int ScanBracketEnd(string s, int start) {
        char open = s[start];
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        int i = start;
        int len = s.Length;
        while (i < len) {
            char c = s[i];
            if (c == '"') { i = ScanStringEnd(s, i); continue; }
            if (c == open) depth++;
            else if (c == close) { depth--; if (depth == 0) return i + 1; }
            i++;
        }
        throw new Exception("unterminated bracket");
    }

    // Scan a JSON value starting at s[start]; return the index one past the value.
    static int ScanValueEnd(string s, int start) {
        int i = start;
        int len = s.Length;
        while (i < len && IsWs(s[i])) i++;
        if (i >= len) throw new Exception("EOF in value");
        char c = s[i];
        if (c == '"') return ScanStringEnd(s, i);
        if (c == '{' || c == '[') return ScanBracketEnd(s, i);
        int j = i;
        while (j < len) {
            char cc = s[j];
            if (cc == ',' || cc == '}' || cc == ']' || IsWs(cc)) break;
            j++;
        }
        return j;
    }

    // Decode a JSON string literal (with surrounding quotes) into its plain
    // text form. Used only for matching envelope keys ("id"/"record").
    static string JsonUnescape(string raw) {
        if (raw.Length < 2 || raw[0] != '"') return raw;
        var sb = new StringBuilder(raw.Length - 2);
        int i = 1;
        int end = raw.Length - 1;
        while (i < end) {
            char c = raw[i];
            if (c == '\\' && i + 1 < end) {
                char nxt = raw[i + 1];
                switch (nxt) {
                    case '"':  sb.Append('"');  i += 2; break;
                    case '\\': sb.Append('\\'); i += 2; break;
                    case '/':  sb.Append('/');  i += 2; break;
                    case 'n':  sb.Append('\n'); i += 2; break;
                    case 'r':  sb.Append('\r'); i += 2; break;
                    case 't':  sb.Append('\t'); i += 2; break;
                    case 'b':  sb.Append('\b'); i += 2; break;
                    case 'f':  sb.Append('\f'); i += 2; break;
                    case 'u':
                        if (i + 6 <= end) {
                            try {
                                int cp = Convert.ToInt32(raw.Substring(i + 2, 4), 16);
                                sb.Append((char) cp);
                                i += 6;
                            } catch { sb.Append(nxt); i += 2; }
                        } else { sb.Append(nxt); i += 2; }
                        break;
                    default: sb.Append(nxt); i += 2; break;
                }
            } else { sb.Append(c); i++; }
        }
        return sb.ToString();
    }

    class Envelope {
        public string RawIdJson;
        public string RawRecordJson;
    }

    // Extract raw "id" and "record" value substrings from an envelope line.
    // Substring extraction only — no dependency on the JCS library.
    static Envelope ParseEnvelope(string line) {
        var env = new Envelope();
        int len = line.Length;
        int i = 0;
        while (i < len && IsWs(line[i])) i++;
        if (i >= len || line[i] != '{') throw new Exception("envelope not object");
        i++;
        while (i < len) {
            while (i < len && (IsWs(line[i]) || line[i] == ',')) i++;
            if (i >= len || line[i] == '}') break;
            if (line[i] != '"') throw new Exception("expected key");
            int keyEnd = ScanStringEnd(line, i);
            string key = JsonUnescape(line.Substring(i, keyEnd - i));
            i = keyEnd;
            while (i < len && IsWs(line[i])) i++;
            if (i >= len || line[i] != ':') throw new Exception("expected colon");
            i++;
            int valStart = i;
            while (valStart < len && IsWs(line[valStart])) valStart++;
            int valEnd = ScanValueEnd(line, i);
            string rawVal = line.Substring(valStart, valEnd - valStart);
            if (key == "id") env.RawIdJson = rawVal;
            else if (key == "record") env.RawRecordJson = rawVal;
            i = valEnd;
        }
        return env;
    }

    // Regex fallback for id extraction. Returns the id as its JSON
    // representation, or "null" when no id can be found.
    static string ExtractIdJsonFallback(string line) {
        try {
            var m = ID_REGEX.Match(line);
            if (m.Success) {
                if (m.Groups[1].Success) return "\"" + m.Groups[1].Value + "\"";
                if (m.Groups[2].Success) return m.Groups[2].Value;
            }
        } catch { /* fall through */ }
        return "null";
    }

    // JCS-canonicalize the input record and sign; returns the raw response
    // body ({"canonical":...,"signature_hex":...}). Daemon mode wraps this
    // with id/ok; one-shot mode emits it verbatim (byte-identical to
    // pre-daemon output).
    static string SignRecord(SignatureAlgorithm algo, Key key, string recordJson) {
        // JCS canonicalize the input record. This is the entire payload we sign.
        string canonical = new JsonCanonicalizer(recordJson).GetEncodedString();
        byte[] sig = algo.Sign(key, Encoding.UTF8.GetBytes(canonical));
        var sb = new StringBuilder();
        sb.Append("{\"canonical\":");
        JsonEscape(sb, canonical);
        sb.Append(",\"signature_hex\":\"");
        sb.Append(Convert.ToHexStringLower(sig));
        sb.Append("\"}");
        return sb.ToString();
    }

    public static void Main() {
        string keyHex = Environment.GetEnvironmentVariable("SIGNING_KEY_HEX");
        if (string.IsNullOrEmpty(keyHex)) {
            Console.Error.WriteLine("SIGNING_KEY_HEX required");
            Environment.Exit(1);
        }
        byte[] seed = Convert.FromHexString(keyHex);

        var algo = SignatureAlgorithm.Ed25519;
        // Keep the NSec Key handle warm for the process lifetime; in daemon
        // mode this amortizes libsodium key-import cost across every record.
        using var key = Key.Import(algo, seed, KeyBlobFormat.RawPrivateKey);

        string daemonEnv = Environment.GetEnvironmentVariable("DAEMON_MODE");
        bool daemon = !string.IsNullOrEmpty(daemonEnv) && daemonEnv != "0";

        if (daemon) {
            string line;
            while ((line = Console.In.ReadLine()) != null) {
                if (line.Length == 0) continue;
                string outLine;
                string idJson = "null";
                try {
                    Envelope env;
                    try {
                        env = ParseEnvelope(line);
                        if (env.RawIdJson != null) idJson = env.RawIdJson;
                    } catch (Exception) {
                        idJson = ExtractIdJsonFallback(line);
                        throw;
                    }
                    if (env.RawRecordJson == null) throw new Exception("record field missing");
                    string body = SignRecord(algo, key, env.RawRecordJson);
                    // body is {"canonical":...,"signature_hex":...} — splice
                    // id/ok in front by stripping the leading '{'.
                    outLine = "{\"id\":" + idJson + ",\"ok\":true," + body.Substring(1);
                } catch (Exception ex) {
                    string msg = ex.Message ?? ex.GetType().Name;
                    try {
                        var sb = new StringBuilder();
                        sb.Append("{\"id\":").Append(idJson).Append(",\"ok\":false,\"error\":");
                        JsonEscape(sb, msg);
                        sb.Append('}');
                        outLine = sb.ToString();
                    } catch {
                        outLine = "{\"id\":" + idJson + ",\"ok\":false,\"error\":\"internal_encode_failure\"}";
                    }
                }
                Console.Out.WriteLine(outLine);
                Console.Out.Flush();
            }
            return;
        }

        // One-shot mode: read all of stdin as one record. Byte-identical to
        // pre-daemon output (no id/ok wrapping).
        string input = Console.In.ReadToEnd();
        Console.Write(SignRecord(algo, key, input));
    }
}

}

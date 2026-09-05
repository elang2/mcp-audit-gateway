// Cross-emitter matrix — C# signer.
// Uses NSec.Cryptography (a managed libsodium binding) for Ed25519.
// Tuple-array canonical form matching ../verify.mjs etc.
//
// Note: we avoid System.Text.Json for the canonical output because its
// JavaScriptEncoder escapes surrogate pairs even in UnsafeRelaxedJsonEscaping /
// UnicodeRanges.All modes, breaking byte-identical cross-SDK convergence for
// astral-plane characters (e.g. emoji). Uses a hand-rolled compact emitter.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

class Program {
    static readonly string[] FIELD_ORDER = new[] {
        "id","timestamp","method","toolName","namespace","upstream",
        "principal","durationMs","success","errorCode","previousHash"
    };

    static int CompareUtf16Be(string a, string b) {
        byte[] ba = Encoding.BigEndianUnicode.GetBytes(a);
        byte[] bb = Encoding.BigEndianUnicode.GetBytes(b);
        int len = Math.Min(ba.Length, bb.Length);
        for (int i = 0; i < len; i++) {
            int cmp = ba[i] - bb[i];
            if (cmp != 0) return cmp;
        }
        return ba.Length - bb.Length;
    }

    static object JsonToPoco(JsonElement e) {
        switch (e.ValueKind) {
            case JsonValueKind.Null: return null;
            case JsonValueKind.True: return true;
            case JsonValueKind.False: return false;
            case JsonValueKind.String: return e.GetString();
            case JsonValueKind.Number:
                if (!e.TryGetInt64(out long i)) throw new Exception("unsafe number (non-integer): " + e);
                if (Math.Abs(i) > (1L << 53) - 1) throw new Exception("unsafe integer " + i);
                return i;
            case JsonValueKind.Array: {
                var list = new List<object>();
                foreach (var x in e.EnumerateArray()) list.Add(JsonToPoco(x));
                return list;
            }
            case JsonValueKind.Object: {
                var dict = new List<KeyValuePair<string, object>>();
                foreach (var p in e.EnumerateObject()) dict.Add(new KeyValuePair<string, object>(p.Name, JsonToPoco(p.Value)));
                return dict;
            }
            default: throw new Exception("unsupported ValueKind " + e.ValueKind);
        }
    }

    static object CanonicalizeValue(object v) {
        if (v == null) return null;
        if (v is bool || v is string || v is long) return v;
        if (v is List<object> arr) {
            var inner = new List<object>();
            foreach (var x in arr) inner.Add(CanonicalizeValue(x));
            return new List<object> { "L", inner };
        }
        if (v is List<KeyValuePair<string, object>> obj) {
            var keys = new List<string>();
            foreach (var kv in obj) keys.Add(kv.Key);
            keys.Sort(CompareUtf16Be);
            var lookup = new Dictionary<string, object>();
            foreach (var kv in obj) lookup[kv.Key] = kv.Value;
            var pairs = new List<object>();
            foreach (var k in keys) {
                pairs.Add(new List<object> { k, CanonicalizeValue(lookup[k]) });
            }
            return new List<object> { "M", pairs };
        }
        throw new Exception("unsupported type " + v.GetType());
    }

    static void JsonEscape(StringBuilder sb, string s) {
        sb.Append('"');
        foreach (var c in s) {
            switch (c) {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static void JsonSerialize(StringBuilder sb, object v) {
        if (v == null) { sb.Append("null"); return; }
        if (v is bool b) { sb.Append(b ? "true" : "false"); return; }
        if (v is long l) { sb.Append(l); return; }
        if (v is string s) { JsonEscape(sb, s); return; }
        if (v is List<object> arr) {
            sb.Append('[');
            for (int i = 0; i < arr.Count; i++) {
                if (i > 0) sb.Append(',');
                JsonSerialize(sb, arr[i]);
            }
            sb.Append(']');
            return;
        }
        throw new Exception("unsupported at emit " + v.GetType());
    }

    static string Canonicalize(JsonElement record) {
        var ordered = new List<object>();
        var recordDict = new Dictionary<string, JsonElement>();
        foreach (var p in record.EnumerateObject()) recordDict[p.Name] = p.Value;
        foreach (string k in FIELD_ORDER) {
            JsonElement e;
            object cv;
            if (recordDict.TryGetValue(k, out e)) cv = CanonicalizeValue(JsonToPoco(e));
            else cv = null;
            ordered.Add(new List<object> { k, cv });
        }
        foreach (string opt in new[] {"decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"}) {
            JsonElement e;
            if (recordDict.TryGetValue(opt, out e) && e.ValueKind != JsonValueKind.Null) {
                ordered.Add(new List<object> { opt, CanonicalizeValue(JsonToPoco(e)) });
            }
        }
        var sb = new StringBuilder();
        JsonSerialize(sb, ordered);
        return sb.ToString();
    }

    static string SignRecord(SignatureAlgorithm algo, Key key, JsonElement record) {
        string canonical = Canonicalize(record);
        byte[] sig = algo.Sign(key, Encoding.UTF8.GetBytes(canonical));
        var output = new Dictionary<string, string> {
            {"canonical", canonical},
            {"signature_hex", Convert.ToHexStringLower(sig)}
        };
        return JsonSerializer.Serialize(output);
    }

    static void Main() {
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
                // idBox is set as soon as we can parse the "id" field, so
                // both the ok and error branches echo the caller's id verbatim.
                object idBox = null;
                try {
                    using var lineDoc = JsonDocument.Parse(line);
                    var root = lineDoc.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) {
                        throw new Exception("input must be a JSON object");
                    }
                    if (root.TryGetProperty("id", out var idE)) {
                        idBox = idE.Clone();
                    }
                    if (!root.TryGetProperty("record", out var record)) {
                        throw new Exception("missing record");
                    }
                    string canonical = Canonicalize(record);
                    byte[] sig = algo.Sign(key, Encoding.UTF8.GetBytes(canonical));
                    var okOut = new Dictionary<string, object> {
                        {"id", idBox},
                        {"ok", true},
                        {"canonical", canonical},
                        {"signature_hex", Convert.ToHexStringLower(sig)}
                    };
                    outLine = JsonSerializer.Serialize(okOut);
                } catch (Exception ex) {
                    var errOut = new Dictionary<string, object> {
                        {"id", idBox},
                        {"ok", false},
                        {"error", ex.Message}
                    };
                    outLine = JsonSerializer.Serialize(errOut);
                }
                Console.Out.WriteLine(outLine);
                Console.Out.Flush();
            }
            return;
        }

        string input = Console.In.ReadToEnd();
        using var oneShotDoc = JsonDocument.Parse(input);
        Console.Write(SignRecord(algo, key, oneShotDoc.RootElement));
    }
}

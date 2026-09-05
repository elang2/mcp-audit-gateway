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

    static string VerifyPayload(SignatureAlgorithm algo,
                                 Dictionary<string, PublicKey> pubKeyCache,
                                 JsonElement payload) {
        var record = payload.GetProperty("record");
        string sigHex = payload.GetProperty("signature_hex").GetString();
        string pubHex = payload.GetProperty("public_key_hex").GetString();

        PublicKey pubKey;
        if (!pubKeyCache.TryGetValue(pubHex, out pubKey)) {
            byte[] pubBytes = Convert.FromHexString(pubHex);
            pubKey = PublicKey.Import(algo, pubBytes, KeyBlobFormat.RawPublicKey);
            pubKeyCache[pubHex] = pubKey;
        }
        byte[] sigBytes = Convert.FromHexString(sigHex);

        bool verified = false;
        string canonical = null;
        try {
            canonical = Canonicalize(record);
            verified = algo.Verify(pubKey, Encoding.UTF8.GetBytes(canonical), sigBytes);
        } catch (Exception e) {
            canonical = "ERROR: " + e.Message;
        }

        var output = new Dictionary<string, object> {
            {"verified", verified},
            {"local_canonical", canonical},
            {"sig_hex", sigHex}
        };
        return JsonSerializer.Serialize(output);
    }

    static void Main() {
        var algo = SignatureAlgorithm.Ed25519;
        // Cache imported PublicKey handles by hex; in daemon mode this keeps
        // the NSec key state warm across records with the same signer.
        var pubKeyCache = new Dictionary<string, PublicKey>();

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
                    if (!root.TryGetProperty("signature_hex", out var sigE)) {
                        throw new Exception("missing signature_hex");
                    }
                    if (!root.TryGetProperty("public_key_hex", out var pubE)) {
                        throw new Exception("missing public_key_hex");
                    }
                    string sigHex = sigE.GetString();
                    string pubHex = pubE.GetString();

                    PublicKey pubKey;
                    if (!pubKeyCache.TryGetValue(pubHex, out pubKey)) {
                        byte[] pubBytes = Convert.FromHexString(pubHex);
                        pubKey = PublicKey.Import(algo, pubBytes, KeyBlobFormat.RawPublicKey);
                        pubKeyCache[pubHex] = pubKey;
                    }
                    byte[] sigBytes = Convert.FromHexString(sigHex);

                    string canonical = Canonicalize(record);
                    bool verified = algo.Verify(pubKey, Encoding.UTF8.GetBytes(canonical), sigBytes);

                    var okOut = new Dictionary<string, object> {
                        {"id", idBox},
                        {"ok", true},
                        {"verified", verified},
                        {"local_canonical", canonical}
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
        Console.Write(VerifyPayload(algo, pubKeyCache, oneShotDoc.RootElement));
    }
}

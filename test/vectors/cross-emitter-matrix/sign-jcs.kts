// Cross-emitter matrix — Kotlin signer, JCS variant.
// Reuses the cyberphone Java reference implementation
// (io.github.erdtman:java-json-canonicalization:1.1, vendored at
// ../runners/java-json-canonicalization-1.1.jar) via JVM interop.
// Java 15+ stdlib Ed25519 via java.security.
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
// Run (with JCS jar on the classpath):
//   JCS_JAR=../runners/java-json-canonicalization-1.1.jar
//   SIGNING_KEY_HEX=... kotlin -cp $JCS_JAR sign-jcs.kts < record.json
//   SIGNING_KEY_HEX=... DAEMON_MODE=1 kotlin -cp $JCS_JAR sign-jcs.kts

import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.util.regex.Pattern

// Minimal JSON string escape sufficient for the {"canonical":...} envelope.
// The canonical form is JCS-clean already; we only need to re-embed it as
// a JSON string value.
fun jsonEscape(str: String): String {
    val sb = StringBuilder(str.length + 2)
    sb.append('"')
    for (c in str) {
        when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            '\b' -> sb.append("\\b")
            '' -> sb.append("\\f")
            else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
    }
    sb.append('"')
    return sb.toString()
}

fun isWs(c: Char) = c == ' ' || c == '\t' || c == '\n' || c == '\r'

// Scan a JSON string starting at s[start] (which must be '"'); return the
// index one past the closing quote. Handles backslash escapes.
fun scanStringEnd(s: String, start: Int): Int {
    var i = start + 1
    while (i < s.length) {
        val c = s[i]
        if (c == '\\') { i += 2; continue }
        if (c == '"') return i + 1
        i++
    }
    throw RuntimeException("unterminated string")
}

// Scan a JSON object or array starting at s[start]; return the index one
// past the matching close bracket. Respects string boundaries.
fun scanBracketEnd(s: String, start: Int): Int {
    val open = s[start]
    val close = if (open == '{') '}' else ']'
    var depth = 0
    var i = start
    while (i < s.length) {
        val c = s[i]
        if (c == '"') { i = scanStringEnd(s, i); continue }
        if (c == open) depth++
        else if (c == close) { depth--; if (depth == 0) return i + 1 }
        i++
    }
    throw RuntimeException("unterminated bracket")
}

// Scan a JSON value starting at s[start]; return the index one past the value.
fun scanValueEnd(s: String, start: Int): Int {
    var i = start
    while (i < s.length && isWs(s[i])) i++
    if (i >= s.length) throw RuntimeException("EOF in value")
    val c = s[i]
    if (c == '"') return scanStringEnd(s, i)
    if (c == '{' || c == '[') return scanBracketEnd(s, i)
    var j = i
    while (j < s.length) {
        val cc = s[j]
        if (cc == ',' || cc == '}' || cc == ']' || isWs(cc)) break
        j++
    }
    return j
}

// Decode a JSON string literal (with surrounding quotes) into its plain
// text form. Used only for matching envelope keys ("id"/"record").
fun jsonUnescape(raw: String): String {
    if (raw.length < 2 || raw[0] != '"') return raw
    val sb = StringBuilder(raw.length - 2)
    var i = 1
    val end = raw.length - 1
    while (i < end) {
        val c = raw[i]
        if (c == '\\' && i + 1 < end) {
            val nxt = raw[i + 1]
            when (nxt) {
                '"' -> { sb.append('"'); i += 2 }
                '\\' -> { sb.append('\\'); i += 2 }
                '/' -> { sb.append('/'); i += 2 }
                'n' -> { sb.append('\n'); i += 2 }
                'r' -> { sb.append('\r'); i += 2 }
                't' -> { sb.append('\t'); i += 2 }
                'b' -> { sb.append('\b'); i += 2 }
                'f' -> { sb.append(''); i += 2 }
                'u' -> {
                    if (i + 6 <= end) {
                        try {
                            val cp = raw.substring(i + 2, i + 6).toInt(16)
                            sb.append(cp.toChar())
                            i += 6
                        } catch (_: NumberFormatException) { sb.append(nxt); i += 2 }
                    } else { sb.append(nxt); i += 2 }
                }
                else -> { sb.append(nxt); i += 2 }
            }
        } else { sb.append(c); i++ }
    }
    return sb.toString()
}

data class Envelope(var rawIdJson: String? = null, var rawRecordJson: String? = null)

// Extract raw "id" and "record" value substrings from an envelope line.
// Substring extraction only — no dependency on the JCS jar.
fun parseEnvelope(line: String): Envelope {
    val env = Envelope()
    var i = 0
    val len = line.length
    while (i < len && isWs(line[i])) i++
    if (i >= len || line[i] != '{') throw RuntimeException("envelope not object")
    i++
    while (i < len) {
        while (i < len && (isWs(line[i]) || line[i] == ',')) i++
        if (i >= len || line[i] == '}') break
        if (line[i] != '"') throw RuntimeException("expected key")
        val keyEnd = scanStringEnd(line, i)
        val key = jsonUnescape(line.substring(i, keyEnd))
        i = keyEnd
        while (i < len && isWs(line[i])) i++
        if (i >= len || line[i] != ':') throw RuntimeException("expected colon")
        i++
        var valStart = i
        while (valStart < len && isWs(line[valStart])) valStart++
        val valEnd = scanValueEnd(line, i)
        val rawVal = line.substring(valStart, valEnd)
        when (key) {
            "id" -> env.rawIdJson = rawVal
            "record" -> env.rawRecordJson = rawVal
        }
        i = valEnd
    }
    return env
}

// Regex fallback for id extraction — matches the wire-protocol regex used
// by the other daemons. Returns the id as its JSON representation, or
// "null" when no id can be found.
val ID_REGEX: Pattern = Pattern.compile(
    "\"id\"\\s*:\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(-?\\d+(?:\\.\\d+)?))"
)

fun extractIdJsonFallback(line: String): String {
    return try {
        val m = ID_REGEX.matcher(line)
        if (m.find()) {
            val s = m.group(1)
            if (s != null) "\"$s\""
            else m.group(2) ?: "null"
        } else "null"
    } catch (_: Throwable) { "null" }
}

val keyHex = System.getenv("SIGNING_KEY_HEX") ?: error("SIGNING_KEY_HEX required")
val seed = ByteArray(32) { i -> keyHex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

val paramSpec = NamedParameterSpec("Ed25519")
val keySpec = EdECPrivateKeySpec(paramSpec, seed)
val kf = KeyFactory.getInstance("Ed25519")
val privKey = kf.generatePrivate(keySpec)
// Reuse a single Signature instance across records; initSign() resets internal state.
val sigInstance = Signature.getInstance("Ed25519")

// JCS-canonicalize and sign a record's raw JSON substring. The
// JsonCanonicalizer reference is inside this function so callers can catch
// NoClassDefFoundError on FIRST invocation and surface "erdtman jar missing"
// per record rather than crashing the daemon.
fun signRecord(recordJson: String): String {
    val canonical = org.erdtman.jcs.JsonCanonicalizer(recordJson).getEncodedString()
    sigInstance.initSign(privKey)
    sigInstance.update(canonical.toByteArray(StandardCharsets.UTF_8))
    val sig = sigInstance.sign()
    val sigHex = sig.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    return """{"canonical":${jsonEscape(canonical)},"signature_hex":"$sigHex"}"""
}

fun classifyError(inner: Throwable): String {
    var t: Throwable? = inner
    while (t != null) {
        if (t is NoClassDefFoundError || t is ClassNotFoundException) {
            val tm = t.message
            if (tm != null && (tm.contains("org/erdtman") || tm.contains("org.erdtman"))) {
                return "erdtman jar missing"
            }
            return "erdtman jar missing"
        }
        t = t.cause
    }
    return inner.message ?: inner.javaClass.simpleName
}

if (System.getenv("DAEMON_MODE") == "1") {
    // Daemon mode: newline-delimited JSON envelopes on stdin, one NDJSON
    // response per line on stdout. Signer/key/Signature state stays warm
    // across records to amortize Kotlin/JVM cold start.
    val reader = BufferedReader(InputStreamReader(System.`in`, StandardCharsets.UTF_8))
    val out = System.out
    while (true) {
        val line = reader.readLine() ?: break
        if (line.isBlank()) continue
        // Paranoid outer try guarantees exactly one response line per input.
        val response: String = try {
            var idJson = "null"
            try {
                val env = parseEnvelope(line)
                env.rawIdJson?.let { idJson = it }
                val rec = env.rawRecordJson ?: throw RuntimeException("record field missing")
                val body = signRecord(rec)
                // body is {"canonical":...,"signature_hex":...} — splice
                // id/ok in front by stripping the leading '{'.
                """{"id":$idJson,"ok":true,${body.substring(1)}"""
            } catch (inner: Throwable) {
                if (idJson == "null") idJson = extractIdJsonFallback(line)
                val errMsg = classifyError(inner)
                try {
                    """{"id":$idJson,"ok":false,"error":${jsonEscape(errMsg)}}"""
                } catch (_: Throwable) {
                    """{"id":$idJson,"ok":false,"error":"internal_encode_failure"}"""
                }
            }
        } catch (_: Throwable) {
            """{"id":null,"ok":false,"error":"internal_encode_failure"}"""
        }
        out.print(response)
        out.print('\n')
        out.flush()
    }
} else {
    val input = BufferedReader(InputStreamReader(System.`in`, StandardCharsets.UTF_8)).readText()
    print(signRecord(input))
}

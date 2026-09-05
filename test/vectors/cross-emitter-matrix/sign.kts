// Cross-emitter matrix — Kotlin signer.
// Kotlin script. Uses Java stdlib Ed25519 (Java 15+).
// Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.
// Run: SIGNING_KEY_HEX=... kotlinc -script sign.kts < record.json

import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec

val FIELD_ORDER = listOf(
    "id","timestamp","method","toolName","namespace","upstream",
    "principal","durationMs","success","errorCode","previousHash"
)

// Minimal JSON parser + canonicalizer using a small hand-rolled parser
// to avoid pulling in kotlinx.serialization which needs the module system.

class Parser(val s: String) {
    var i = 0
    fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
    fun parse(): Any? { skipWs(); return parseValue() }
    fun parseValue(): Any? {
        skipWs()
        return when {
            i < s.length && s[i] == '"' -> parseString()
            i < s.length && s[i] == '{' -> parseObject()
            i < s.length && s[i] == '[' -> parseArray()
            i < s.length && (s[i] == 't' || s[i] == 'f') -> parseBool()
            i < s.length && s[i] == 'n' -> parseNull()
            else -> parseNumber()
        }
    }
    fun parseString(): String {
        i++ // skip "
        val sb = StringBuilder()
        while (i < s.length && s[i] != '"') {
            if (s[i] == '\\') {
                i++
                when (s[i]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        val hex = s.substring(i + 1, i + 5)
                        sb.append(hex.toInt(16).toChar())
                        i += 4
                    }
                }
                i++
            } else {
                sb.append(s[i++])
            }
        }
        i++ // skip closing "
        return sb.toString()
    }
    fun parseObject(): Map<String, Any?> {
        i++ // skip {
        val m = linkedMapOf<String, Any?>()
        skipWs()
        while (i < s.length && s[i] != '}') {
            skipWs()
            val key = parseString()
            skipWs()
            i++ // skip :
            m[key] = parseValue()
            skipWs()
            if (i < s.length && s[i] == ',') i++
            skipWs()
        }
        i++ // skip }
        return m
    }
    fun parseArray(): List<Any?> {
        i++ // skip [
        val list = mutableListOf<Any?>()
        skipWs()
        while (i < s.length && s[i] != ']') {
            list.add(parseValue())
            skipWs()
            if (i < s.length && s[i] == ',') i++
            skipWs()
        }
        i++ // skip ]
        return list
    }
    fun parseBool(): Boolean = if (s[i] == 't') { i += 4; true } else { i += 5; false }
    fun parseNull(): Any? { i += 4; return null }
    fun parseNumber(): Any {
        val start = i
        while (i < s.length && (s[i].isDigit() || s[i] == '-' || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+')) i++
        val str = s.substring(start, i)
        return if (str.contains('.') || str.contains('e') || str.contains('E')) str.toDouble() else str.toLong()
    }
}

fun jsonEscape(str: String): String {
    val sb = StringBuilder("\"")
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
    sb.append("\"")
    return sb.toString()
}

fun jsonSerialize(v: Any?): String {
    return when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is Long -> v.toString()
        is Double -> throw RuntimeException("unsafe float")
        is String -> jsonEscape(v)
        is List<*> -> "[" + v.joinToString(",") { jsonSerialize(it) } + "]"
        is Map<*, *> -> {
            val entries = v.entries.joinToString(",") { (k, vv) -> jsonEscape(k as String) + ":" + jsonSerialize(vv) }
            "{$entries}"
        }
        else -> throw RuntimeException("unsupported ${v::class}")
    }
}

fun utf16BeBytes(str: String): ByteArray {
    return str.toByteArray(java.nio.charset.Charset.forName("UTF-16BE"))
}

fun canonicalizeValue(v: Any?): Any? {
    if (v == null) return null
    if (v is Boolean) return v
    if (v is String) return v
    if (v is Long) {
        if (Math.abs(v) > (1L shl 53) - 1) throw RuntimeException("unsafe integer $v")
        return v
    }
    if (v is Int) {
        val l = v.toLong()
        return l
    }
    if (v is Double || v is Float) throw RuntimeException("unsafe float")
    if (v is List<*>) return listOf("L", v.map { canonicalizeValue(it) })
    if (v is Map<*, *>) {
        @Suppress("UNCHECKED_CAST")
        val m = v as Map<String, Any?>
        val keys = m.keys.sortedWith(Comparator { a, b ->
            val ba = utf16BeBytes(a); val bb = utf16BeBytes(b)
            val len = minOf(ba.size, bb.size)
            for (i in 0 until len) {
                val cmp = (ba[i].toInt() and 0xff) - (bb[i].toInt() and 0xff)
                if (cmp != 0) return@Comparator cmp
            }
            ba.size - bb.size
        })
        return listOf("M", keys.map { k -> listOf(k, canonicalizeValue(m[k])) })
    }
    throw RuntimeException("unsupported ${v::class}")
}

fun canonicalize(record: Map<String, Any?>): String {
    val ordered = mutableListOf<List<Any?>>()
    for (k in FIELD_ORDER) {
        ordered.add(listOf(k, canonicalizeValue(record[k])))
    }
    for (opt in listOf("decisionContextDigest", "extensionsDigest", "aiInvocation", "parties")) {
        if (record[opt] != null) {
            ordered.add(listOf(opt, canonicalizeValue(record[opt])))
        }
    }
    return jsonSerialize(ordered)
}

val keyHex = System.getenv("SIGNING_KEY_HEX") ?: error("SIGNING_KEY_HEX required")
val seed = ByteArray(32) { i -> keyHex.substring(i*2, i*2+2).toInt(16).toByte() }

val paramSpec = NamedParameterSpec("Ed25519")
val keySpec = EdECPrivateKeySpec(paramSpec, seed)
val kf = KeyFactory.getInstance("Ed25519")
val privKey = kf.generatePrivate(keySpec)
// Reuse a single Signature instance across records; initSign() resets internal state.
val sigInstance = Signature.getInstance("Ed25519")

fun signRecord(record: Map<String, Any?>): Pair<String, String> {
    val canonical = canonicalize(record)
    sigInstance.initSign(privKey)
    sigInstance.update(canonical.toByteArray(StandardCharsets.UTF_8))
    val sig = sigInstance.sign()
    val sigHex = sig.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    return Pair(canonical, sigHex)
}

fun signOne(recordJson: String): String {
    @Suppress("UNCHECKED_CAST")
    val record = Parser(recordJson).parse() as Map<String, Any?>
    val (canonical, sigHex) = signRecord(record)
    return """{"canonical":${jsonEscape(canonical)},"signature_hex":"$sigHex"}"""
}

if (System.getenv("DAEMON_MODE") == "1") {
    // Daemon mode: id-wrapped envelopes {"id":"...","record":{...}} on stdin, one
    // id-wrapped JSON response per line on stdout. Signer/key/Signature state stays
    // warm across records to amortize Kotlin/JVM cold start.
    val reader = BufferedReader(InputStreamReader(System.`in`))
    val out = System.out
    while (true) {
        val line = reader.readLine() ?: break
        if (line.isBlank()) continue
        var id: String? = null
        val response = try {
            @Suppress("UNCHECKED_CAST")
            val envelope = Parser(line).parse() as Map<String, Any?>
            id = envelope["id"] as? String
            @Suppress("UNCHECKED_CAST")
            val record = envelope["record"] as? Map<String, Any?>
                ?: throw RuntimeException("missing record")
            val (canonical, sigHex) = signRecord(record)
            val idPart = if (id != null) jsonEscape(id!!) else "null"
            """{"id":$idPart,"ok":true,"canonical":${jsonEscape(canonical)},"signature_hex":"$sigHex"}"""
        } catch (e: Exception) {
            val idPart = if (id != null) jsonEscape(id!!) else "null"
            """{"id":$idPart,"ok":false,"error":${jsonEscape(e.message ?: e.toString())}}"""
        }
        out.print(response)
        out.print('\n')
        out.flush()
    }
} else {
    val input = BufferedReader(InputStreamReader(System.`in`)).readText()
    print(signOne(input))
}

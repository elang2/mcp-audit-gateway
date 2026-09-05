// Cross-emitter matrix — Kotlin verifier.
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

val FIELD_ORDER = listOf(
    "id","timestamp","method","toolName","namespace","upstream",
    "principal","durationMs","success","errorCode","previousHash"
)

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
        i++
        val sb = StringBuilder()
        while (i < s.length && s[i] != '"') {
            if (s[i] == '\\') {
                i++
                when (s[i]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> { sb.append(s.substring(i+1, i+5).toInt(16).toChar()); i += 4 }
                    else -> sb.append(s[i])
                }
                i++
            } else sb.append(s[i++])
        }
        i++
        return sb.toString()
    }
    fun parseObject(): Map<String, Any?> {
        i++
        val m = linkedMapOf<String, Any?>()
        skipWs()
        while (i < s.length && s[i] != '}') {
            skipWs(); val k = parseString(); skipWs(); i++
            m[k] = parseValue(); skipWs()
            if (i < s.length && s[i] == ',') i++
            skipWs()
        }
        i++
        return m
    }
    fun parseArray(): List<Any?> {
        i++
        val list = mutableListOf<Any?>()
        skipWs()
        while (i < s.length && s[i] != ']') {
            list.add(parseValue()); skipWs()
            if (i < s.length && s[i] == ',') i++
            skipWs()
        }
        i++
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
            else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
    }
    sb.append("\"")
    return sb.toString()
}

fun jsonSerialize(v: Any?): String = when (v) {
    null -> "null"
    is Boolean -> v.toString()
    is Long -> v.toString()
    is String -> jsonEscape(v)
    is List<*> -> "[" + v.joinToString(",") { jsonSerialize(it) } + "]"
    is Map<*, *> -> "{" + v.entries.joinToString(",") { (k, vv) -> jsonEscape(k as String) + ":" + jsonSerialize(vv) } + "}"
    else -> throw RuntimeException("unsupported ${v::class}")
}

fun utf16BeBytes(str: String): ByteArray = str.toByteArray(java.nio.charset.Charset.forName("UTF-16BE"))

fun canonicalizeValue(v: Any?): Any? {
    if (v == null) return null
    if (v is Boolean) return v
    if (v is String) return v
    if (v is Long) {
        if (Math.abs(v) > (1L shl 53) - 1) throw RuntimeException("unsafe integer $v")
        return v
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
    for (k in FIELD_ORDER) ordered.add(listOf(k, canonicalizeValue(record[k])))
    for (opt in listOf("decisionContextDigest", "extensionsDigest", "aiInvocation", "parties")) {
        if (record[opt] != null) ordered.add(listOf(opt, canonicalizeValue(record[opt])))
    }
    return jsonSerialize(ordered)
}

// SPKI DER prefix for Ed25519 raw public keys.
val spkiPrefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
// Reuse KeyFactory + Signature across records; verifier public key changes per record.
val kf = KeyFactory.getInstance("Ed25519")
val sigInstance = Signature.getInstance("Ed25519")

fun verifyRecord(record: Map<String, Any?>, sigHex: String, pubHex: String): Pair<Boolean, String> {
    val spki = ByteArray(12 + 32).also {
        System.arraycopy(spkiPrefix, 0, it, 0, 12)
        for (i in 0 until 32) it[12 + i] = pubHex.substring(i*2, i*2+2).toInt(16).toByte()
    }
    val pubKey = kf.generatePublic(X509EncodedKeySpec(spki))
    val sig = ByteArray(64) { i -> sigHex.substring(i*2, i*2+2).toInt(16).toByte() }

    val canonical = canonicalize(record)
    val verified = try {
        sigInstance.initVerify(pubKey)
        sigInstance.update(canonical.toByteArray(StandardCharsets.UTF_8))
        sigInstance.verify(sig)
    } catch (e: Exception) { false }
    return Pair(verified, canonical)
}

fun verifyOne(payloadJson: String): String {
    @Suppress("UNCHECKED_CAST")
    val payload = Parser(payloadJson).parse() as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val record = payload["record"] as Map<String, Any?>
    val sigHex = payload["signature_hex"] as String
    val pubHex = payload["public_key_hex"] as String
    val (verified, canonical) = verifyRecord(record, sigHex, pubHex)
    return """{"verified":$verified,"local_canonical":${jsonEscape(canonical)},"sig_hex":"$sigHex"}"""
}

if (System.getenv("DAEMON_MODE") == "1") {
    // Daemon mode: id-wrapped envelopes {"id":"...","record":{...},"signature_hex":"...",
    // "public_key_hex":"..."} on stdin, one id-wrapped JSON response per line on stdout.
    // KeyFactory/Signature stay warm across records to amortize Kotlin/JVM cold start.
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
            val sigHex = envelope["signature_hex"] as? String
                ?: throw RuntimeException("missing signature_hex")
            val pubHex = envelope["public_key_hex"] as? String
                ?: throw RuntimeException("missing public_key_hex")
            val (verified, canonical) = verifyRecord(record, sigHex, pubHex)
            val idPart = if (id != null) jsonEscape(id!!) else "null"
            """{"id":$idPart,"ok":true,"verified":$verified,"local_canonical":${jsonEscape(canonical)}}"""
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
    print(verifyOne(input))
}

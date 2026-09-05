// Cross-emitter matrix — Java verifier.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;

public class Verify {
    static final String[] FIELD_ORDER = {
        "id","timestamp","method","toolName","namespace","upstream",
        "principal","durationMs","success","errorCode","previousHash"
    };
    static final ObjectMapper M = new ObjectMapper();

    static Object canonicalizeValue(Object v) {
        if (v == null) return NullNode.getInstance();
        if (v instanceof NullNode) return NullNode.getInstance();
        if (v instanceof BooleanNode) return v;
        if (v instanceof TextNode) return v;
        if (v instanceof IntNode || v instanceof LongNode) {
            long i = ((JsonNode)v).longValue();
            if (Math.abs(i) > (1L << 53) - 1) throw new RuntimeException("unsafe number " + i);
            return v;
        }
        if (v instanceof DoubleNode || v instanceof FloatNode) {
            throw new RuntimeException("unsafe number (float): " + v);
        }
        if (v instanceof ArrayNode) {
            ArrayNode inner = M.createArrayNode();
            for (JsonNode x : (ArrayNode)v) inner.add((JsonNode)canonicalizeValue(x));
            ArrayNode tagged = M.createArrayNode();
            tagged.add("L");
            tagged.add(inner);
            return tagged;
        }
        if (v instanceof ObjectNode) {
            ObjectNode obj = (ObjectNode)v;
            List<String> keys = new ArrayList<>();
            obj.fieldNames().forEachRemaining(keys::add);
            keys.sort((a,b) -> {
                byte[] ba = a.getBytes(StandardCharsets.UTF_16BE);
                byte[] bb = b.getBytes(StandardCharsets.UTF_16BE);
                int len = Math.min(ba.length, bb.length);
                for (int i = 0; i < len; i++) {
                    int cmp = (ba[i] & 0xff) - (bb[i] & 0xff);
                    if (cmp != 0) return cmp;
                }
                return ba.length - bb.length;
            });
            ArrayNode pairs = M.createArrayNode();
            for (String k : keys) {
                ArrayNode pair = M.createArrayNode();
                pair.add(k);
                pair.add((JsonNode)canonicalizeValue(obj.get(k)));
                pairs.add(pair);
            }
            ArrayNode tagged = M.createArrayNode();
            tagged.add("M");
            tagged.add(pairs);
            return tagged;
        }
        throw new RuntimeException("unsupported type " + v.getClass());
    }

    static String canonicalize(JsonNode record) throws Exception {
        ArrayNode ordered = M.createArrayNode();
        for (String k : FIELD_ORDER) {
            JsonNode v = record.get(k);
            ArrayNode pair = M.createArrayNode();
            pair.add(k);
            pair.add((JsonNode)canonicalizeValue(v == null ? NullNode.getInstance() : v));
            ordered.add(pair);
        }
        for (String opt : new String[]{"decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"}) {
            JsonNode v = record.get(opt);
            if (v != null && !v.isNull()) {
                ArrayNode pair = M.createArrayNode();
                pair.add(opt);
                pair.add((JsonNode)canonicalizeValue(v));
                ordered.add(pair);
            }
        }
        return M.writeValueAsString(ordered);
    }

    static final byte[] SPKI_PREFIX = new byte[]{
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    static ObjectNode verifyOne(JsonNode payload, KeyFactory kf) throws Exception {
        String pubHex = payload.get("public_key_hex").asText();
        String sigHex = payload.get("signature_hex").asText();
        JsonNode record = payload.get("record");

        // Build SPKI DER: 12-byte header + 32-byte pubkey
        byte[] spki = new byte[12 + 32];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, 12);
        for (int i = 0; i < 32; i++) spki[12 + i] = (byte)Integer.parseInt(pubHex.substring(i*2, i*2+2), 16);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spki);
        PublicKey pubKey = kf.generatePublic(keySpec);

        byte[] sigBytes = new byte[64];
        for (int i = 0; i < 64; i++) sigBytes[i] = (byte)Integer.parseInt(sigHex.substring(i*2, i*2+2), 16);

        boolean verified = false;
        String canonical = null;
        try {
            canonical = canonicalize(record);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pubKey);
            sig.update(canonical.getBytes(StandardCharsets.UTF_8));
            verified = sig.verify(sigBytes);
        } catch (Exception e) {
            canonical = "ERROR: " + e.getMessage();
        }
        ObjectNode out = M.createObjectNode();
        out.put("verified", verified);
        out.put("local_canonical", canonical);
        out.put("sig_hex", sigHex);
        return out;
    }

    public static void main(String[] args) throws Exception {
        // Warm KeyFactory reused across records in daemon mode.
        KeyFactory kf = KeyFactory.getInstance("Ed25519");

        String daemon = System.getenv("DAEMON_MODE");
        if (daemon != null && daemon.equals("1")) {
            // Daemon mode: id-wrapped envelopes {"id": "...", "record": {...},
            // "signature_hex": "...", "public_key_hex": "..."} on stdin, id-wrapped
            // JSON responses on stdout. Loop until EOF; a per-record failure emits
            // {"id": <id>, "ok": false, "error": "..."} and continues.
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
            String line;
            while ((line = in.readLine()) != null) {
                if (line.isEmpty()) continue;
                String id = null;
                try {
                    JsonNode envelope = M.readTree(line);
                    JsonNode idNode = envelope.get("id");
                    id = (idNode == null || idNode.isNull()) ? null : idNode.asText();
                    // verifyOne reads record/signature_hex/public_key_hex from the payload;
                    // the extra "id" key in the envelope is ignored by it.
                    ObjectNode verified = verifyOne(envelope, kf);
                    ObjectNode result = M.createObjectNode();
                    if (id != null) result.put("id", id); else result.putNull("id");
                    result.put("ok", true);
                    result.put("verified", verified.get("verified").asBoolean());
                    result.set("local_canonical", verified.get("local_canonical"));
                    out.println(M.writeValueAsString(result));
                } catch (Exception e) {
                    ObjectNode err = M.createObjectNode();
                    if (id != null) err.put("id", id); else err.putNull("id");
                    err.put("ok", false);
                    err.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
                    out.println(M.writeValueAsString(err));
                }
                out.flush();
            }
            return;
        }

        // One-shot mode: single payload on stdin, single JSON object on stdout (no newline).
        JsonNode payload = M.readTree(System.in);
        ObjectNode result = verifyOne(payload, kf);
        System.out.print(M.writeValueAsString(result));
    }
}

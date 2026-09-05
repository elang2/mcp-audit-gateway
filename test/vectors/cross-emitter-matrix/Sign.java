// Cross-emitter matrix — Java signer.
// Java 15+ stdlib Ed25519 via java.security.
// Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
// Build+run: javac Sign.java && SIGNING_KEY_HEX=... java Sign  (reads JSON stdin)

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;

public class Sign {
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

    static ObjectNode signOne(JsonNode record, PrivateKey privKey) throws Exception {
        String canonical = canonicalize(record);
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(privKey);
        sig.update(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = sig.sign();
        StringBuilder hex = new StringBuilder();
        for (byte b : sigBytes) hex.append(String.format("%02x", b & 0xff));
        ObjectNode out = M.createObjectNode();
        out.put("canonical", canonical);
        out.put("signature_hex", hex.toString());
        return out;
    }

    public static void main(String[] args) throws Exception {
        String keyHex = System.getenv("SIGNING_KEY_HEX");
        if (keyHex == null) { System.err.println("SIGNING_KEY_HEX required"); System.exit(1); }
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)Integer.parseInt(keyHex.substring(i*2, i*2+2), 16);

        // Warm instances reused across records in daemon mode.
        NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
        EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(paramSpec, seed);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        PrivateKey privKey = kf.generatePrivate(keySpec);

        String daemon = System.getenv("DAEMON_MODE");
        if (daemon != null && daemon.equals("1")) {
            // Daemon mode: id-wrapped envelopes {"id": "...", "record": {...}} on stdin,
            // id-wrapped JSON responses on stdout. Loop until EOF; a per-record failure
            // emits {"id": <id>, "ok": false, "error": "..."} and continues.
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
                    JsonNode record = envelope.get("record");
                    if (record == null || record.isNull()) throw new RuntimeException("missing record");
                    ObjectNode signed = signOne(record, privKey);
                    ObjectNode result = M.createObjectNode();
                    if (id != null) result.put("id", id); else result.putNull("id");
                    result.put("ok", true);
                    result.set("canonical", signed.get("canonical"));
                    result.set("signature_hex", signed.get("signature_hex"));
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

        // One-shot mode: single record on stdin, single JSON object on stdout (no newline).
        JsonNode record = M.readTree(System.in);
        ObjectNode result = signOne(record, privKey);
        System.out.print(M.writeValueAsString(result));
    }
}

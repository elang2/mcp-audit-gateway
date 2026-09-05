#!/usr/bin/env php
<?php
// Cross-emitter matrix — PHP verifier.
const FIELD_ORDER = [
    'id','timestamp','method','toolName','namespace','upstream',
    'principal','durationMs','success','errorCode','previousHash'
];

function canonicalize_value($v) {
    if (is_null($v)) return null;
    if (is_bool($v)) return $v;
    if (is_string($v)) return $v;
    if (is_int($v)) {
        if (abs($v) > (1 << 53) - 1) throw new Exception("unsafe integer $v");
        return $v;
    }
    if (is_float($v)) throw new Exception("unsafe number (float)");
    if (is_array($v)) {
        // JSON arrays only — decoded via stdClass mode so associative arrays
        // never arrive here.
        $inner = [];
        foreach ($v as $vv) {
            $inner[] = canonicalize_value($vv);
        }
        return ['L', $inner];
    }
    if (is_object($v)) {
        // JSON objects arrive as stdClass. foreach over stdClass preserves
        // numeric-string property names as strings (unlike (array)$v or
        // get_object_vars(), both of which coerce "2" back to int 2).
        $keys = [];
        foreach ($v as $k => $vv) {
            $keys[] = $k;
        }
        usort($keys, function($a, $b) {
            $ba = mb_convert_encoding((string)$a, 'UTF-16BE', 'UTF-8');
            $bb = mb_convert_encoding((string)$b, 'UTF-16BE', 'UTF-8');
            return strcmp($ba, $bb);
        });
        $pairs = [];
        foreach ($keys as $k) {
            $pairs[] = [(string)$k, canonicalize_value($v->{$k})];
        }
        return ['M', $pairs];
    }
    throw new Exception("unsupported type");
}

function canonicalize($record) {
    // $record is a stdClass (json_decode without assoc flag).
    $ordered = [];
    foreach (FIELD_ORDER as $k) {
        $v = property_exists($record, $k) ? $record->{$k} : null;
        $ordered[] = [$k, canonicalize_value($v)];
    }
    foreach (['decisionContextDigest', 'extensionsDigest', 'aiInvocation', 'parties'] as $opt) {
        if (property_exists($record, $opt) && $record->{$opt} !== null) {
            $ordered[] = [$opt, canonicalize_value($record->{$opt})];
        }
    }
    return json_encode($ordered, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

if (getenv('DAEMON_MODE') === '1') {
    // Env pinning — only set if missing, don't override caller-set values.
    if (getenv('LC_ALL') === false) putenv('LC_ALL=C.UTF-8');
    if (getenv('PYTHONIOENCODING') === false) putenv('PYTHONIOENCODING=utf-8');
    // Cache decoded public keys across records — the reason daemon mode
    // exists is to amortize hex2bin and PHP startup over the batch.
    $pubKeyCache = [];
    while (($line = fgets(STDIN)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($line === '') continue;
        // Best-effort id extraction from the raw line, so we can still emit
        // an {ok:false} correlated response when json_decode itself fails
        // (e.g. lone-surrogate \u escapes in an adversarial record).
        $id = null;
        if (preg_match('/"id"\s*:\s*"((?:\\\\.|[^"\\\\])*)"/', $line, $m)) {
            $decodedId = json_decode('"' . $m[1] . '"');
            $id = ($decodedId === null && json_last_error() !== JSON_ERROR_NONE) ? $m[1] : $decodedId;
        } elseif (preg_match('/"id"\s*:\s*(-?\d+)/', $line, $m)) {
            $id = (int)$m[1];
        } elseif (preg_match('/"id"\s*:\s*(true|false|null)/', $line, $m)) {
            $id = ($m[1] === 'true') ? true : (($m[1] === 'false') ? false : null);
        }
        // Wrap parse + canonicalize + verify in one try so any failure — including
        // json_decode returning null on invalid \u escapes — emits {ok:false}
        // instead of silently dropping the response and breaking id correlation.
        try {
            // stdClass mode preserves numeric-string keys in nested objects.
            $req = json_decode($line);
            if ($req === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("json_decode: " . json_last_error_msg());
            }
            if (!is_object($req) || !property_exists($req, 'id')) {
                throw new Exception("missing id or non-object request");
            }
            $id = $req->id;
            $pkHex = property_exists($req, 'public_key_hex') ? $req->public_key_hex : null;
            $sigHex = property_exists($req, 'signature_hex') ? $req->signature_hex : null;
            if (!is_string($pkHex) || !is_string($sigHex) || !property_exists($req, 'record')) {
                throw new Exception("missing public_key_hex/signature_hex/record");
            }
            if (!isset($pubKeyCache[$pkHex])) {
                $pubKeyCache[$pkHex] = hex2bin($pkHex);
            }
            $pubKey = $pubKeyCache[$pkHex];
            $sig = hex2bin($sigHex);
            $canonical = canonicalize($req->record);
            $verified = sodium_crypto_sign_verify_detached($sig, $canonical, $pubKey);
            $resp = [
                'id' => $id,
                'ok' => true,
                'verified' => $verified,
                'local_canonical' => $canonical,
                'sig_hex' => $sigHex,
            ];
        } catch (\Throwable $e) {
            if ($id === null) {
                // Truly no id anywhere on the line → cannot correlate; skip.
                continue;
            }
            $resp = ['id' => $id, 'ok' => false, 'error' => $e->getMessage()];
        }
        // JSON_INVALID_UTF8_SUBSTITUTE: raw invalid UTF-8 in the error message
        // (or in the id, when the parent sent an adversarial id) must not cause
        // json_encode to return false — that would drop the rejection response
        // and break the paper's rejection-map signal.
        $out = json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($out === false) {
            $out = '{"id":' . json_encode((string)$id, JSON_INVALID_UTF8_SUBSTITUTE)
                 . ',"ok":false,"error":"json_encode failed: ' . json_last_error_msg() . '"}';
        }
        fwrite(STDOUT, $out . "\n");
        fflush(STDOUT);
    }
    exit(0);
}

$input = stream_get_contents(STDIN);
// stdClass mode preserves numeric-string keys in nested JSON objects.
$payload = json_decode($input);

$pubKey = hex2bin($payload->public_key_hex);
$sig = hex2bin($payload->signature_hex);

$verified = false;
$canonical = null;
try {
    $canonical = canonicalize($payload->record);
    $verified = sodium_crypto_sign_verify_detached($sig, $canonical, $pubKey);
} catch (Exception $e) {
    $canonical = "ERROR: " . $e->getMessage();
}

echo json_encode([
    'verified' => $verified,
    'local_canonical' => $canonical,
    'sig_hex' => $payload->signature_hex,
]);

#!/usr/bin/env php
<?php
// Cross-emitter matrix — PHP signer.
// Uses libsodium (built-in since PHP 7.2) for Ed25519.
// Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.

const FIELD_ORDER = [
    'id','timestamp','method','toolName','namespace','upstream',
    'principal','durationMs','success','errorCode','previousHash'
];

function assertWellFormed($str) {
    // PHP JSON strings are already UTF-8; check for lone surrogates by checking valid UTF-8
    if (!mb_check_encoding($str, 'UTF-8')) {
        throw new Exception("invalid UTF-8");
    }
}

function canonicalize_value($v) {
    if (is_null($v)) return null;
    if (is_bool($v)) return $v;
    if (is_string($v)) { assertWellFormed($v); return $v; }
    if (is_int($v)) {
        if (abs($v) > (1 << 53) - 1) throw new Exception("unsafe integer $v");
        return $v;
    }
    if (is_float($v)) throw new Exception("unsafe number (float)");
    if (is_array($v)) {
        // JSON arrays only — decoded via stdClass mode so associative arrays
        // never arrive here. Preserve order, canonicalize element-wise.
        $inner = [];
        foreach ($v as $vv) {
            $inner[] = canonicalize_value($vv);
        }
        return ['L', $inner];
    }
    if (is_object($v)) {
        // JSON objects arrive as stdClass. foreach over stdClass preserves
        // numeric-string property names as strings (unlike (array)$v or
        // get_object_vars(), both of which coerce "2" back to int 2 and
        // silently break the ["2", false] canonical form).
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
            $ks = (string)$k;
            assertWellFormed($ks);
            $pairs[] = [$ks, canonicalize_value($v->{$k})];
        }
        return ['M', $pairs];
    }
    throw new Exception("unsupported type: " . gettype($v));
}

function canonicalize($record) {
    // $record is a stdClass (json_decode without assoc flag). Access via
    // property syntax so numeric-string keys are preserved at every depth.
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

$keyHex = getenv('SIGNING_KEY_HEX');
if (empty($keyHex)) { fwrite(STDERR, "SIGNING_KEY_HEX required\n"); exit(1); }
$seed = hex2bin($keyHex);
$keypair = sodium_crypto_sign_seed_keypair($seed);
$secretKey = sodium_crypto_sign_secretkey($keypair);

if (getenv('DAEMON_MODE') === '1') {
    // Env pinning — only set if missing, don't override caller-set values.
    if (getenv('LC_ALL') === false) putenv('LC_ALL=C.UTF-8');
    if (getenv('PYTHONIOENCODING') === false) putenv('PYTHONIOENCODING=utf-8');
    // $secretKey (loaded above) is reused across every record — the reason
    // daemon mode exists is to amortize key/keypair setup and PHP startup.
    while (($line = fgets(STDIN)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($line === '') continue;
        // Best-effort id extraction from the raw line, so we can still emit
        // an {ok:false} correlated response when json_decode itself fails
        // (e.g. lone-surrogate \u escapes in an adversarial record). String
        // ids preferred; fall back to integer/null/bool literals.
        $id = null;
        if (preg_match('/"id"\s*:\s*"((?:\\\\.|[^"\\\\])*)"/', $line, $m)) {
            // JSON-decode just the extracted id literal so it matches what
            // the parent process sent (unescape \n, \uXXXX, etc.).
            $decodedId = json_decode('"' . $m[1] . '"');
            $id = ($decodedId === null && json_last_error() !== JSON_ERROR_NONE) ? $m[1] : $decodedId;
        } elseif (preg_match('/"id"\s*:\s*(-?\d+)/', $line, $m)) {
            $id = (int)$m[1];
        } elseif (preg_match('/"id"\s*:\s*(true|false|null)/', $line, $m)) {
            $id = ($m[1] === 'true') ? true : (($m[1] === 'false') ? false : null);
        }
        // Wrap parse + canonicalize + sign in one try so any failure — including
        // json_decode returning null on invalid \u escapes — emits {ok:false}
        // instead of silently dropping the response and breaking id correlation.
        try {
            // stdClass mode (no `true` second arg) so nested JSON objects with
            // numeric-string keys like {"2":false} do NOT get their keys
            // coerced to integers via PHP's array-key semantics. Compare to
            // json_decode($line, true), which silently mangles {"2":false}
            // into array(2 => false) and then emits [2,false] in canonical.
            $req = json_decode($line);
            if ($req === null && json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("json_decode: " . json_last_error_msg());
            }
            if (!is_object($req) || !property_exists($req, 'id')) {
                throw new Exception("missing id or non-object request");
            }
            $id = $req->id;
            if (!property_exists($req, 'record') || !is_object($req->record)) {
                throw new Exception("missing record");
            }
            $canonical = canonicalize($req->record);
            $sig = sodium_crypto_sign_detached($canonical, $secretKey);
            $resp = [
                'id' => $id,
                'ok' => true,
                'canonical' => $canonical,
                'signature_hex' => bin2hex($sig),
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
            // Last-resort fallback: emit a minimal envelope so the parent still
            // sees a correlated rejection instead of a silent drop.
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
$record = json_decode($input);
if (!is_object($record)) { fwrite(STDERR, "invalid JSON input\n"); exit(1); }

$canonical = canonicalize($record);
$sig = sodium_crypto_sign_detached($canonical, $secretKey);

echo json_encode([
    'canonical' => $canonical,
    'signature_hex' => bin2hex($sig),
]);

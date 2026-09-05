#!/usr/bin/env php
<?php
// Cross-emitter matrix — PHP JCS (RFC 8785) signer.
//
// Uses `root23/php-json-canonicalization` from Packagist. Byte-identical to the
// cyberphone RFC 8785 reference vectors across all 6 testdata files (arrays,
// french, structures, unicode, values, weird) — verified by the byte-identity
// check in the return summary of the runner-dispatch change that introduced
// this file.
//
// This variant emits RFC 8785 canonical bytes rather than the tuple-array form.
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
//
// ---------------------------------------------------------------------------
// Daemon protocol (must match the wire contract in fuzzing/fuzz-runner.mjs):
// ---------------------------------------------------------------------------
//   Startup env: DAEMON_MODE=1
//                CANONICAL_FORM=jcs           (informational; algorithm is fixed)
//                SIGNING_KEY_HEX=<64 hex chars>
//
//   Request  (one NDJSON line per record on stdin):
//       {"id": "<opaque-string>", "record": <object>}
//
//   Response (one NDJSON line per request on stdout, flushed):
//       {"id":"<same-id>","ok":true,"canonical":"<str>","signature_hex":"<hex>"}
//     — or —
//       {"id":"<same-id>","ok":false,"error":"<short-string>"}
//
// One-shot mode (DAEMON_MODE unset): reads a single record on stdin, writes
// a single JSON object (canonical + signature_hex) to stdout.

declare(strict_types=1);

$autoloadCandidates = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    '/tmp/php-jcs/vendor/autoload.php',
];
$autoloaded = false;
foreach ($autoloadCandidates as $path) {
    if (is_file($path)) {
        require $path;
        $autoloaded = true;
        break;
    }
}
if (!$autoloaded) {
    fwrite(STDERR, "root23/php-json-canonicalization autoload not found; run composer require root23/php-json-canonicalization\n");
    exit(1);
}

use Root23\JsonCanonicalizer\JsonCanonicalizer;

const FIELD_REQUIRED = [
    'id', 'timestamp', 'method', 'toolName', 'namespace', 'upstream',
    'principal', 'durationMs', 'success', 'errorCode', 'previousHash',
];
const FIELD_OPTIONAL = ['decisionContextDigest', 'extensionsDigest', 'aiInvocation', 'parties'];

function build_record($record): array {
    // "Drop null optionals" convention shared with the tuple-array signer so
    // the two variants are semantically comparable on the same record. JCS
    // then re-orders all keys itself (lexicographic by UTF-16 code units).
    //
    // Accepts stdClass (from json_decode without the assoc flag) so nested
    // objects with numeric-string keys — e.g. extensionsDigest: {"2":false}
    // — do NOT get their keys coerced to integers via PHP array-key
    // semantics. The top-level (array) cast on stdClass is safe because
    // FIELD_REQUIRED and FIELD_OPTIONAL are all non-numeric strings; nested
    // stdClass values pass through untouched by reference.
    $arr = is_object($record) ? (array)$record : (array)$record;
    $out = [];
    foreach (FIELD_REQUIRED as $k) {
        $out[$k] = $arr[$k] ?? null;
    }
    foreach (FIELD_OPTIONAL as $k) {
        if (isset($arr[$k]) && $arr[$k] !== null) {
            $out[$k] = $arr[$k];
        }
    }
    return $out;
}

$keyHex = getenv('SIGNING_KEY_HEX');
if (empty($keyHex)) {
    fwrite(STDERR, "SIGNING_KEY_HEX required\n");
    exit(1);
}
$seed = hex2bin($keyHex);
$keypair = sodium_crypto_sign_seed_keypair($seed);
$secretKey = sodium_crypto_sign_secretkey($keypair);

$canonicalizer = new JsonCanonicalizer();

function canonicalize_and_sign(JsonCanonicalizer $canonicalizer, string $secretKey, $record): array {
    $canonical = $canonicalizer->canonicalize(build_record($record));
    $sig = sodium_crypto_sign_detached($canonical, $secretKey);
    return ['canonical' => $canonical, 'signature_hex' => bin2hex($sig)];
}

function emit_line(array $obj): void {
    // JSON_UNESCAPED_SLASHES + JSON_UNESCAPED_UNICODE match the tuple-array
    // signer's wire format for the "canonical" string field (which is a JSON
    // *string* payload embedded in the response envelope, not the canonical
    // bytes themselves — those are already fully specified by JCS).
    echo json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
}

if (getenv('DAEMON_MODE') === '1') {
    // Env pinning — only set if missing, don't override caller-set values.
    if (getenv('LC_ALL') === false) putenv('LC_ALL=C.UTF-8');
    if (getenv('PYTHONIOENCODING') === false) putenv('PYTHONIOENCODING=utf-8');
    // $secretKey (loaded above) is reused across every record — the reason
    // daemon mode exists is to amortize key/keypair setup and PHP startup.
    while (($line = fgets(STDIN)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($line === '') { continue; }
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
            // stdClass mode (no `true` second arg) so nested JSON objects
            // with numeric-string keys — e.g. extensionsDigest: {"2":false}
            // — do NOT get their keys coerced to integers via PHP array-key
            // semantics before we hand them to the canonicalizer.
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
            $result = canonicalize_and_sign($canonicalizer, $secretKey, $req->record);
            $resp = [
                'id' => $id,
                'ok' => true,
                'canonical' => $result['canonical'],
                'signature_hex' => $result['signature_hex'],
            ];
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            // Best-effort sanitize to valid UTF-8 so json_encode doesn't itself
            // raise and drop the rejection tag.
            if (!mb_check_encoding($msg, 'UTF-8')) {
                $msg = mb_convert_encoding($msg, 'UTF-8', 'UTF-8');
            }
            $msg = substr($msg, 0, 200);
            $resp = ['id' => $id, 'ok' => false, 'error' => $msg];
        }
        // JSON_INVALID_UTF8_SUBSTITUTE: raw invalid UTF-8 in the error message
        // (or in the id, when the parent sent an adversarial id) must not cause
        // json_encode to return false — that would drop the rejection response
        // and break the paper's rejection-map signal.
        $out = json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
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
} else {
    $input = stream_get_contents(STDIN);
    // stdClass mode preserves numeric-string keys in nested JSON objects.
    $record = json_decode($input);
    $result = canonicalize_and_sign($canonicalizer, $secretKey, $record);
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

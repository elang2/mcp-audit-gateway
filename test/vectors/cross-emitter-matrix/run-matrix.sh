#!/usr/bin/env bash
# Cross-emitter signature-verification matrix orchestration.
# Runs each (signer SDK, verifier SDK) pair against a shared vector set
# and produces matrix-results.json.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Generate a fresh Ed25519 keypair for this run. Private key = 32 bytes hex,
# public key = 32 bytes hex derived from private.
PRIV_HEX=$(node -e "const c = require('node:crypto'); const {privateKey} = c.generateKeyPairSync('ed25519', {privateKeyEncoding:{type:'pkcs8',format:'der'}}); console.log(privateKey.subarray(-32).toString('hex'));")
PUB_HEX=$(node -e "
const c = require('node:crypto');
const priv = Buffer.from(process.argv[1], 'hex');
const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), priv]);
const key = c.createPrivateKey({key: der, format:'der', type:'pkcs8'});
const pub = c.createPublicKey(key).export({type:'spki', format:'der'});
console.log(pub.subarray(-32).toString('hex'));
" "$PRIV_HEX")

export SIGNING_KEY_HEX="$PRIV_HEX"

# Vector set: 8 real conformance vectors from ../canonicalization.json (flat records),
# plus 5 nested-field vectors from ./nested-vectors.json (aiInvocation, parties,
# extensionsDigest, unicode keys) that exercise the canonicalize_value recursion,
# plus 25 adversarial vectors from ./adversarial-vectors.json (Wycheproof-style:
# unicode normalization, lone surrogates, deep nesting, integer edges, empty
# structures, mixed-type arrays, sort collisions, ZWJ/RTL, escaped controls,
# boolean-integer overlap).
# MATRIX_MODE options: flat | nested | adversarial | all
: "${MATRIX_MODE:=all}"
# Extraction uses node rather than jq because adversarial-vectors.json contains
# lone-surrogate escapes (\uD83D, \uDE00, reversed pairs) as REJECT-behavior
# test inputs; jq refuses to parse those but node's JSON.parse accepts them.
if [ "$MATRIX_MODE" = "flat" ]; then
  VECTORS=$(node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync('../canonicalization.json','utf-8')).canonicalization.map(v => v.record)))")
elif [ "$MATRIX_MODE" = "nested" ]; then
  VECTORS=$(node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync('nested-vectors.json','utf-8')).vectors.map(v => v.record)))")
elif [ "$MATRIX_MODE" = "adversarial" ]; then
  VECTORS=$(node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync('adversarial-vectors.json','utf-8')).vectors.map(v => v.record)))")
else
  VECTORS=$(node -e "
const fs = require('fs');
const flat = JSON.parse(fs.readFileSync('../canonicalization.json','utf-8')).canonicalization.map(v => v.record);
const nested = JSON.parse(fs.readFileSync('nested-vectors.json','utf-8')).vectors.map(v => v.record);
const adv = JSON.parse(fs.readFileSync('adversarial-vectors.json','utf-8')).vectors.map(v => v.record);
console.log(JSON.stringify([...flat, ...nested, ...adv]));
")
fi

# Build Go binaries fresh
go build -o /tmp/mcp-sign-go sign.go
go build -o /tmp/mcp-verify-go verify.go

# Compile Java classes fresh
JAVA_CP="../runners/jackson-core.jar:../runners/jackson-databind.jar:../runners/jackson-annotations.jar:."
javac -cp "$JAVA_CP" Sign.java Verify.java 2>/dev/null

JACKSON_CP_KT="../runners/jackson-core.jar:../runners/jackson-databind.jar:../runners/jackson-annotations.jar"

RUST_SIGN="$(cd "$DIR/rust-signer" && pwd)/target/release/sign"
RUST_VERIFY="$(cd "$DIR/rust-signer" && pwd)/target/release/verify"

CS_SIGN_DLL="$(find "$DIR/csharp-signer/bin/Release" -name Sign.dll | head -1)"
CS_VERIFY_DLL="$(find "$DIR/csharp-verifier/bin/Release" -name Verify.dll | head -1)"
DOTNET_BIN="$HOME/.dotnet/dotnet"

SIGNERS=(
  "ts:node sign.mjs"
  "py:python3 sign.py"
  "go:/tmp/mcp-sign-go"
  "rb:ruby sign.rb"
  "jv:java -cp $JAVA_CP Sign"
  "sw:swift sign.swift"
  "ph:php sign.php"
  "kt:kotlin -cp $JACKSON_CP_KT sign.kts"
  "rs:$RUST_SIGN"
  "cs:$DOTNET_BIN $CS_SIGN_DLL"
)
VERIFIERS=(
  "ts:node verify.mjs"
  "py:python3 verify.py"
  "go:/tmp/mcp-verify-go"
  "rb:ruby verify.rb"
  "jv:java -cp $JAVA_CP Verify"
  "sw:swift verify.swift"
  "ph:php verify.php"
  "kt:kotlin -cp $JACKSON_CP_KT verify.kts"
  "rs:$RUST_VERIFY"
  "cs:$DOTNET_BIN $CS_VERIFY_DLL"
  "buggy:node verify-buggy.mjs"
)

echo "Cross-emitter signature-verification matrix — 10 SDKs + buggy control (all 10 official MCP SDKs)"
echo "Signer: emits (canonical_form, signature) using the SDK's local canonicalizer"
echo "Verifier: recomputes canonical form locally, verifies signature against it"
echo "Public key: $PUB_HEX"
echo ""
echo "Matrix orientation: signer (rows below) → verifier (columns). ✓ = signature verifies. ✗ = fails."
echo ""
printf "| Vector "
for SIGNER_PAIR in "${SIGNERS[@]}"; do
  SIGNER_NAME="${SIGNER_PAIR%%:*}"
  for VERIFIER_PAIR in "${VERIFIERS[@]}"; do
    VERIFIER_NAME="${VERIFIER_PAIR%%:*}"
    printf "| %s→%s " "$SIGNER_NAME" "$VERIFIER_NAME"
  done
done
printf "|\n"
printf "|--------"
for SIGNER_PAIR in "${SIGNERS[@]}"; do
  for VERIFIER_PAIR in "${VERIFIERS[@]}"; do
    printf "|-------"
  done
done
printf "|\n"

RESULTS_JSON="{\"public_key_hex\":\"$PUB_HEX\",\"cells\":[]}"

echo "$VECTORS" | node -e "
const v = JSON.parse(require('fs').readFileSync(0,'utf-8'));
v.forEach((r,i) => console.log(JSON.stringify({idx: i, record: r})));
" | while IFS= read -r LINE; do
  IDX=$(echo "$LINE" | node -e "console.log(JSON.parse(require('fs').readFileSync(0,'utf-8')).idx)")
  RECORD=$(echo "$LINE" | node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync(0,'utf-8')).record))")
  ROW="| $IDX "
  for SIGNER_PAIR in "${SIGNERS[@]}"; do
    SIGNER_NAME="${SIGNER_PAIR%%:*}"
    SIGNER_CMD="${SIGNER_PAIR#*:}"
    SIG_JSON=$(echo "$RECORD" | $SIGNER_CMD 2>/dev/null || echo '{"error":"signer failed"}')
    SIG_HEX=$(echo "$SIG_JSON" | node -e "const j=JSON.parse(require('fs').readFileSync(0,'utf-8')); console.log(j.signature_hex || '')")
    for VERIFIER_PAIR in "${VERIFIERS[@]}"; do
      VERIFIER_NAME="${VERIFIER_PAIR%%:*}"
      VERIFIER_CMD="${VERIFIER_PAIR#*:}"
      PAYLOAD=$(echo "{\"record\":$RECORD,\"signature_hex\":\"$SIG_HEX\",\"public_key_hex\":\"$PUB_HEX\"}")
      VERIFY_OUT=$(echo "$PAYLOAD" | $VERIFIER_CMD 2>/dev/null || echo '{"verified":false}')
      VERIFIED=$(echo "$VERIFY_OUT" | node -e "console.log(JSON.parse(require('fs').readFileSync(0,'utf-8')).verified === true ? '✓' : '✗')")
      ROW="$ROW| $VERIFIED "
    done
  done
  echo "$ROW|"
done

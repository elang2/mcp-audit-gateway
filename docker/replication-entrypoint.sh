#!/usr/bin/env bash
# replication-entrypoint.sh
# ---------------------------------------------------------------------------
# Dispatch script for the mcp-emitter-matrix Docker image. Routes the
# `docker run <image> <cmd>` first argument to the correct in-container
# action:
#
#   smoke      run the cross-SDK smoke conformance test (all lanes present)
#   stage2     run the full cross-emitter matrix (10x10 signer/verifier)
#   aggregate  aggregate matrix-results.json into a summary table
#   analyze    run the divergence-classification analyzer over the outputs
#   versions   print the pinned toolchain versions and exit 0
#   shell      exec into an interactive bash for debugging
#
# Anything else is passed through to bash -c for maximum flexibility.
# ---------------------------------------------------------------------------

set -euo pipefail

CMD="${1:-smoke}"
shift || true

# The compiled dotnet + rust binaries plus toolchains all need to be on PATH.
export PATH="/usr/local/go/bin:/root/.cargo/bin:/opt/kotlinc/bin:/opt/swift/usr/bin:/usr/share/dotnet:${PATH}"

# Ensure the smoke test can find the .NET dispatch path it expects.
if [ ! -e /root/.dotnet/dotnet ]; then
  mkdir -p /root/.dotnet
  ln -sf /usr/share/dotnet/dotnet /root/.dotnet/dotnet
fi

OUT_DIR="${OUT_DIR:-/work/out}"
mkdir -p "$OUT_DIR"

case "$CMD" in
  smoke)
    echo "[entrypoint] running cross-SDK smoke conformance"
    cd /work
    exec node test/vectors/smoke/smoke-conformance.mjs "$@" \
      2>&1 | tee "$OUT_DIR/smoke.log"
    ;;
  stage2)
    echo "[entrypoint] running full cross-emitter matrix"
    cd /work/test/vectors/cross-emitter-matrix
    exec bash run-matrix.sh "$@" 2>&1 | tee "$OUT_DIR/matrix.log"
    ;;
  aggregate)
    echo "[entrypoint] aggregating matrix-results.json"
    cd /work
    if [ -f test/vectors/cross-emitter-matrix/matrix-results.json ]; then
      jq -r '.cells | length as $n | "cells=\($n)"' \
        test/vectors/cross-emitter-matrix/matrix-results.json
    else
      echo "no matrix-results.json — run 'stage2' first" >&2
      exit 2
    fi
    ;;
  analyze)
    echo "[entrypoint] analyzing matrix output for divergence classes"
    cd /work
    exec node -e "
      const fs=require('fs');
      const p='test/vectors/cross-emitter-matrix/matrix-results.json';
      if (!fs.existsSync(p)) { console.error('run stage2 first'); process.exit(2); }
      const j=JSON.parse(fs.readFileSync(p,'utf-8'));
      const cells=j.cells||[];
      const pass=cells.filter(c=>c.verified).length;
      console.log('cells:', cells.length, 'pass:', pass, 'fail:', cells.length-pass);
    "
    ;;
  versions)
    echo "=== pinned toolchain versions ==="
    node --version              | sed 's/^/node    /'
    python3 --version           | sed 's/^/python  /'
    go version                  | sed 's/^/go      /'
    ruby --version              | sed 's/^/ruby    /'
    java --version 2>&1 | head -1 | sed 's/^/java    /'
    kotlinc -version 2>&1 | tail -1 | sed 's/^/kotlin  /'
    dotnet --version            | sed 's/^/dotnet  /'
    rustc --version             | sed 's/^/rust    /'
    php --version | head -1     | sed 's/^/php     /'
    swift --version 2>&1 | head -1 | sed 's/^/swift   /'
    ;;
  shell)
    exec /bin/bash "$@"
    ;;
  *)
    # Fall through to bash for arbitrary in-container commands.
    exec /bin/bash -c "$CMD $*"
    ;;
esac

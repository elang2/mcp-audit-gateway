# mcp-emitter-matrix — Docker replication container

A single-image replication environment for the cross-emitter
signature-verification matrix. One `docker build` produces a container
with every one of the 10 official MCP-SDK toolchains at pinned versions,
plus the compiled binaries and JVM classes each SDK lane needs.

## Quick start

```bash
# from repo root
docker build -t mcp-emitter-matrix:2026-09-01 \
             -f docker/Dockerfile.replication .

# run the smoke conformance test on all lanes
docker run --rm mcp-emitter-matrix:2026-09-01 smoke

# run the full cross-emitter matrix (10 x 10 signer/verifier)
docker run --rm \
    -v "$(pwd)/out:/work/out" \
    mcp-emitter-matrix:2026-09-01 stage2

# print the pinned toolchain versions
docker run --rm mcp-emitter-matrix:2026-09-01 versions

# drop into a shell for debugging
docker run --rm -it mcp-emitter-matrix:2026-09-01 shell
```

Everything under `/work/out` inside the container is meant to be
mount-bound to a host directory so the matrix outputs and logs survive
past the container's lifetime.

## What's inside

Base image is `ubuntu:22.04`. Each language toolchain is built in its own
stage, then the final stage copies the built artifacts and installs each
SDK's runtime pieces.

| SDK        | Version         | Install source                               |
|------------|-----------------|----------------------------------------------|
| Node.js    | 22.x LTS        | NodeSource apt repo                          |
| Python     | 3.11            | deadsnakes PPA + pip                         |
| Go         | 1.24.7          | official tarball to /usr/local/go            |
| Ruby       | 3.3.8           | source build to /usr/local                   |
| OpenJDK    | 21              | Ubuntu apt                                   |
| Kotlin     | 2.0.21          | GitHub Release zip to /opt/kotlinc           |
| .NET SDK   | 9.0             | Microsoft package repo                       |
| Rust       | 1.98.0          | rustup, minimal profile                      |
| PHP        | 8.3             | ondrej/php PPA + composer                    |
| Swift      | 5.10.1          | swift.org Ubuntu 22.04 tarball               |

Pinned library versions (see `replication.md` for SHA-256):

| Library                                | Version | Consumed by  |
|----------------------------------------|---------|--------------|
| rfc8785                                | 0.1.4   | python JCS   |
| ed25519 gem                            | 1.3.0   | ruby         |
| json-canonicalization gem              | 1.0.0   | ruby JCS     |
| jackson-core / databind / annotations  | 2.16.0  | java, kotlin |
| java-json-canonicalization             | 1.1     | java JCS     |
| NSec.Cryptography                      | 24.4.0  | C#           |
| jsoncanonicalizer NuGet                | 1.0.0   | C# JCS       |
| serde_jcs                              | 0.2     | rust JCS     |
| serde_json_canonicalizer               | 0.3     | rust JCS     |
| ed25519-dalek                          | 2.x     | rust         |
| root23/php-json-canonicalization       | 1.0.1   | php JCS      |

## Entrypoint commands

The container's ENTRYPOINT dispatches on its first argument:

- `smoke` — cross-SDK smoke conformance (default). Streams progress
  to stdout and to `/work/out/smoke.log`.
- `stage2` — full 10 x 10 cross-emitter matrix. Output to
  `/work/out/matrix.log` and `matrix-results.json` in the working
  directory (mount `/work/out` to persist).
- `aggregate` — summarise `matrix-results.json` cell counts.
- `analyze` — divergence-classification pass over the aggregated output.
- `versions` — print pinned toolchain versions and exit.
- `shell` — interactive bash for debugging.

Any other first argument is passed to `bash -c` so ad-hoc commands
(`docker run --rm mcp-emitter-matrix:2026-09-01 "cd test/vectors && ls"`)
work too.

## Swift on Linux — known constraint

The smoke test filters the Swift lane to darwin only via
`extraNeeds: () => process.platform === "darwin"` inside
`test/vectors/smoke/smoke-conformance.mjs`. Inside this Linux container
the Swift toolchain is present, but the smoke lane is skipped by design.
To exercise Swift inside the container:

```bash
docker run --rm -it \
  mcp-emitter-matrix:2026-09-01 \
  bash -c "sed -i 's|process.platform === \"darwin\"|true|g' \
     test/vectors/smoke/smoke-conformance.mjs && \
     node test/vectors/smoke/smoke-conformance.mjs --only=sw"
```

This is documented rather than baked into the image so the darwin lane
stays honest about its Foundation-vs-swift-corelibs-foundation split.

## Reproducing a specific cell

A single matrix cell is a `(signer-SDK, verifier-SDK, canonical-form,
vector-index)` tuple. Once the container is up:

```bash
docker run --rm -it \
  -e SIGNING_KEY_HEX=0000...0042 \
  -e MATRIX_MODE=adversarial \
  mcp-emitter-matrix:2026-09-01 \
  bash -c '
     cd test/vectors/cross-emitter-matrix
     RECORD=$(node -e "console.log(JSON.stringify(JSON.parse(require(\"fs\").readFileSync(\"adversarial-vectors.json\",\"utf-8\")).vectors[7].record))")
     echo "$RECORD" | ruby sign.rb | tee /tmp/sig.json
     PUB=$(node -e "const c=require(\"node:crypto\"); const priv=Buffer.from(process.env.SIGNING_KEY_HEX,\"hex\"); const der=Buffer.concat([Buffer.from(\"302e020100300506032b657004220420\",\"hex\"), priv]); const pub=c.createPublicKey(c.createPrivateKey({key:der,format:\"der\",type:\"pkcs8\"})).export({type:\"spki\",format:\"der\"}); console.log(pub.subarray(-32).toString(\"hex\"))")
     SIG=$(jq -r .signature_hex /tmp/sig.json)
     echo "{\"record\":$RECORD,\"signature_hex\":\"$SIG\",\"public_key_hex\":\"$PUB\"}" \
       | python3 verify.py
  '
```

Every element is set from environment or CLI, so the same command will
produce the same output whenever the same image tag is used.

## Local-only image

This container is NOT pushed to Docker Hub or any registry. The tag
`mcp-emitter-matrix:2026-09-01` is a local reference only. Registry push
is a separate authorization step (see the project's push-permission
rules).

## Files

- `Dockerfile.replication` — multi-stage build definition.
- `replication-entrypoint.sh` — argv-dispatch script baked into the image.
- `replication.md` — reproducibility notes, SHA-256 manifest of pinned
  dependency files, per-cell reproduction recipe.
- `README.md` — this file.

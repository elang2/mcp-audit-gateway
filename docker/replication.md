# Replication — mcp-emitter-matrix Docker image

External reproducibility notes for `docker/Dockerfile.replication`. This
file lets a third party verify they have the same source tree, dependency
pins, and image layout that the original run used.

Last verified: 2026-09-01.

## Prerequisites

- Docker 24.x or later (tested on Docker Engine 29.1.5 CLI). Docker
  Desktop, Colima, and rootless dockerd all work equally well.
- Around 12 GB of free disk for the final image plus its build cache.
- Around 4 GB RAM. The Rust and JVM stages are the memory peaks.
- Internet access during `docker build` to pull the Node, Python, Go,
  Rust, Kotlin, .NET, PHP, and Swift toolchain archives. Once built the
  image runs offline.

## Build

From the repo root:

```bash
docker build \
    -t mcp-emitter-matrix:2026-09-01 \
    -f docker/Dockerfile.replication \
    .
```

A cold build on 8-core hardware takes about 30-45 minutes end to end.
Most of the time is Ruby source compilation and Swift tarball extraction;
after those two stages are cached, incremental rebuilds finish in a
minute or two.

## Run — the four dispatch modes

```bash
# smoke conformance (default when no argument given)
docker run --rm mcp-emitter-matrix:2026-09-01 smoke

# stage 2 — the full cross-emitter matrix
docker run --rm \
    -v "$(pwd)/out:/work/out" \
    mcp-emitter-matrix:2026-09-01 stage2

# aggregate matrix-results.json into a cell-count summary
docker run --rm \
    -v "$(pwd)/out:/work/out" \
    mcp-emitter-matrix:2026-09-01 aggregate

# divergence-class analyzer
docker run --rm \
    -v "$(pwd)/out:/work/out" \
    mcp-emitter-matrix:2026-09-01 analyze
```

Every command mounts `/work/out` as the artifact drop, so `matrix.log`,
`smoke.log`, and any intermediate JSON files persist on the host.

## SHA-256 manifest of pinned dependency files

Verify with `shasum -a 256 -c` after checking out the tree. These are the
files a reproducer needs to be byte-identical to the reference run.

| File (repo-relative) | SHA-256 |
|---|---|
| `package.json`                                                             | `8b83b164958a6ec8163bf672428e04e5e2e0ec28d0d2b0bd2963479e156827bf` |
| `package-lock.json`                                                        | `3f6acc419166e4aae47801ba6e24827cf592299aa4b74dc4efdf77265403204c` |
| `test/vectors/cross-emitter-matrix/rust-signer/Cargo.toml`                 | `e59132fa701cc3031e7a275f69cb287482a6dbb63ad169cb4d0f176e6dc37c3f` |
| `test/vectors/cross-emitter-matrix/rust-signer/Cargo.lock`                 | `c09de12282dd6a1fd1d58572811f723577bc73bb091c0e1afcbca3eb62ba68df` |
| `test/vectors/cross-emitter-matrix/go.mod`                                 | `0ba16b80e8e138e7f636c90d593eda0801b5e1398bd03451347634c6cb9ecfcd` |
| `test/vectors/cross-emitter-matrix/go.sum`                                 | `2a87b37d244867b425fe8b1a9591c01763c3b740a0d6fac5c60a7246ccb04b53` |
| `test/vectors/cross-emitter-matrix/csharp-signer/Sign.csproj`              | `af3e6f26c355a54613a99513cf976edb5e98d03857034f69353114635d864df3` |
| `test/vectors/cross-emitter-matrix/csharp-signer/SignJcs.csproj`           | `c14a0c0881b0a3439cc4e6848931e211a94e19b9e27b140742e047464ef8c3f2` |
| `test/vectors/cross-emitter-matrix/csharp-verifier/Verify.csproj`          | `8bcbeb37b1162b43582984db257cf3ad8697dd89769d363a17e4c712f5cda7a3` |
| `test/vectors/runners/jackson-core.jar` (2.16.0)                           | `d8054ae7c0d1c2d2f55d28e46026ebe5892881f3fab5f439233184381c3b4a1f` |
| `test/vectors/runners/jackson-databind.jar` (2.16.0)                       | `4b364e6850dc89172fcf1d4dd26b8ff5488eda44ff4657e22dd265203dd5ab3c` |
| `test/vectors/runners/jackson-annotations.jar` (2.16.0)                    | `581bd61000ef7648943f781ca05689e56d03f6052748365a8e2b3a9b5d3fa32f` |
| `test/vectors/runners/java-json-canonicalization-1.1.jar`                  | `ed12a01f28d147898312963a1f704e90290b67a61f34fa3a761f41c134f4e691` |

Toolchain archives fetched over the network are pinned by the version
strings in the Dockerfile (`GO_VERSION`, `RUBY_VERSION`, `KOTLIN_VERSION`,
`RUST_VERSION`, `SWIFT_VERSION`) rather than by SHA — replacing them with
`--build-arg` values makes the same Dockerfile reproduce any older or
newer toolchain snapshot. If SHA pinning of the archives themselves
becomes a requirement, the recommended path is to add a `sha256sum -c
<expected>.sha256` line immediately after each `wget` in the stage.

## Pinned toolchain versions (build-arg overridable)

| Toolchain  | Version    | Docker ARG name    |
|------------|------------|--------------------|
| Node.js    | 22.x       | (NodeSource setup) |
| Python     | 3.11       | (deadsnakes)       |
| Go         | 1.24.7     | `GO_VERSION`       |
| Ruby       | 3.3.8      | `RUBY_VERSION`     |
| OpenJDK    | 21         | (apt package)      |
| Kotlin     | 2.0.21     | `KOTLIN_VERSION`   |
| .NET SDK   | 9.0        | (Microsoft repo)   |
| Rust       | 1.98.0     | `RUST_VERSION`     |
| PHP        | 8.3        | (ondrej/php PPA)   |
| Swift      | 5.10.1     | `SWIFT_VERSION`    |

## Reproducing a specific cell

A cell is a `(signer_sdk, verifier_sdk, canonical_form, vector_index)`
tuple. To reproduce, e.g., the Ruby-signer / Python-verifier / adversarial
vector 7 / tuple-array form cell:

```bash
docker run --rm -it \
  -e SIGNING_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000042 \
  mcp-emitter-matrix:2026-09-01 shell

# inside the container:
cd /work/test/vectors/cross-emitter-matrix

# 1. extract the record for vector index 7 from the adversarial corpus
RECORD=$(node -e "console.log(JSON.stringify(JSON.parse(require('fs').readFileSync('adversarial-vectors.json','utf-8')).vectors[7].record))")

# 2. derive the public key from the seed
PUB=$(node -e "
  const c = require('node:crypto');
  const priv = Buffer.from(process.env.SIGNING_KEY_HEX, 'hex');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), priv]);
  const key = c.createPrivateKey({key: der, format:'der', type:'pkcs8'});
  const pub = c.createPublicKey(key).export({type:'spki', format:'der'});
  console.log(pub.subarray(-32).toString('hex'));
")

# 3. sign with the Ruby lane
SIG_JSON=$(echo "$RECORD" | ruby sign.rb)
SIG=$(echo "$SIG_JSON" | jq -r .signature_hex)

# 4. verify with the Python lane
echo "{\"record\":$RECORD,\"signature_hex\":\"$SIG\",\"public_key_hex\":\"$PUB\"}" \
  | python3 verify.py
```

The verifier prints a JSON object with `verified: true|false`. That value
is the single cell result. Repeating the same recipe on any host that
has the same image tag produces the same output byte-for-byte because
every ingredient — key material, vector, canonical form, signer version,
verifier version — is fully pinned.

### Seed convention

The container defaults to seed hex
`0000000000000000000000000000000000000000000000000000000000000042` so
smoke runs are byte-reproducible out of the box. Real research runs
should generate fresh keys per run and pass them in via `SIGNING_KEY_HEX`
so signatures across runs are independent.

## Recording a run

Suggested capture for lab notebooks:

```bash
BUILD_START=$(date -u +%s)
docker build -t mcp-emitter-matrix:2026-09-01 \
             -f docker/Dockerfile.replication . \
             2>&1 | tee build.log
BUILD_END=$(date -u +%s)
IMAGE_ID=$(docker image inspect --format '{{.Id}}' mcp-emitter-matrix:2026-09-01)
IMAGE_SIZE_MB=$(docker image inspect --format '{{.Size}}' mcp-emitter-matrix:2026-09-01 \
                | awk '{print int($1/1024/1024)}')

SMOKE_START=$(date -u +%s)
docker run --rm -v "$PWD/out:/work/out" mcp-emitter-matrix:2026-09-01 smoke \
    2>&1 | tee smoke.log
SMOKE_END=$(date -u +%s)

echo "build seconds: $((BUILD_END - BUILD_START))"
echo "smoke seconds: $((SMOKE_END - SMOKE_START))"
echo "image size MB: $IMAGE_SIZE_MB"
echo "image id     : $IMAGE_ID"
```

Attach `build.log`, `smoke.log`, and the timing block above to the
replication attestation.

## Local-only status

This image is not pushed to any registry. Distribution over Docker Hub
or a private registry is a separate authorization step outside the scope
of this file.

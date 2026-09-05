# Dockerfile.replication.v2 — design notes

Companion to `Dockerfile.replication.v2`. Read this before touching v2, and
before deciding whether v2 replaces v1.

## The problem v2 fixes

`Dockerfile.replication` (v1) built every language toolchain by hand
inside a shared `FROM ubuntu:22.04 AS base` layer. Each stage mixed some
combination of:

- an `apt-get install` that pulls from Ubuntu 22.04's default archives
  (Ruby is 3.0, Python is 3.10, Node is 14 — all too old for our matrix)
- a third-party PPA (`ondrej/php`, `deadsnakes/ppa`)
- a NodeSource curl-piped-to-bash setup script
- a Microsoft `packages-microsoft-prod.deb`
- a direct-from-vendor tarball wget (Go, Ruby, Kotlin, Swift, rustup)

Each of those sources has its own class of transient failure: a PPA GPG
key expiring, a tarball URL redirect changing, an apt archive being
temporarily unavailable, a version being pulled from a repo mid-build.
When one stage failed, fixing it did not de-risk the next stage — a
different vendor, a different retrieval mechanism, a different bug.
Rebuilds routinely surfaced one new failure per fix. That is the
"whack-a-mole" pattern.

## The strategy in v2

Replace "build each toolchain from a base image" with "pull each
toolchain from its own already-built official image". Every language
stage in v2 is `FROM <official-image>` and does nothing else (except
in three specific cases documented below). The final runtime stage
uses `COPY --from=<stage>` to layer each toolchain into a single
runtime image.

The upstream official images all have their own CI:

- `node:22-bookworm` — maintained by the Node.js Docker team
- `python:3.11-bookworm` — maintained by the Python Docker team
- `golang:1.24-bookworm` — maintained by the Go team
- `rust:1.98-slim-bookworm` — maintained by the Rust team
- `ruby:3.3-bookworm` — maintained by the Ruby Docker team
- `php:8.3-cli-bookworm` — maintained by the PHP Docker team
- `eclipse-temurin:21-jdk-jammy` — maintained by the Adoptium project
- `mcr.microsoft.com/dotnet/sdk:9.0-bookworm-slim` — maintained by Microsoft
- `swift:6.0-jammy` — maintained by the Swift open source project
- `composer:2` — maintained by the Composer team

When a stage breaks in v2, the breakage is either in the upstream image
(fixed by the upstream team, we just pull a new tag) or in the specific
COPY-and-symlink glue in our runtime stage (a narrow, well-scoped fix).
There is no scenario where "the Python stage broke because deadsnakes
rotated a GPG key and now the whole matrix build is red for a day".

## Three stages that are NOT pure COPY-only

1. `python-stage` runs `pip install rfc8785 cryptography pynacl` so the
   third-party wheels land in `/usr/local/lib/python3.11/site-packages`
   and travel with the runtime COPY. The alternative — installing at
   runtime — pulls from PyPI on every build, adding a network-flakiness
   surface v2 is explicitly trying to eliminate.
2. `ruby-stage` runs `gem install ed25519 json-canonicalization` for
   the same reason: the gems must be present under
   `/usr/local/lib/ruby/gems/3.3.0` in the runtime image.
3. `php-stage` installs the sodium and gmp PHP extensions via the
   `docker-php-ext-install` helper (bundled with the php-cli image),
   plus `composer require root23/php-json-canonicalization`. Sodium is
   not built-in on the official php:8.3-cli image; the helper does the
   canonical build-from-source-with-libsodium-dev step.
4. `kotlin-stage` is `FROM eclipse-temurin:21-jdk-jammy` (there is no
   first-party official Kotlin image on Docker Hub) and layers the
   JetBrains-published kotlinc zip on top. The kotlinc distribution is
   pure JVM, so it is not sensitive to the underlying OS.

Every other stage is a bare `FROM <official>` with zero commands.

## Runtime base choice: `debian:bookworm-slim`

The user's proposed strategy sketch used `ubuntu:22.04` as the runtime.
v2 uses `debian:bookworm-slim` instead. Rationale:

- The majority of the official language images have `-bookworm` variants
  (Node, Python, Go, Ruby, Rust, PHP, .NET). Using `debian:bookworm-slim`
  as the runtime means those toolchains' binaries are running on
  byte-identical libc to what they were compiled against upstream.
- The exceptions are the JDK, Kotlin (both `-jammy` = Ubuntu 22.04), and
  Swift (`-jammy` only, no bookworm variant published). Java bytecode is
  libc-agnostic. Swift ships its own stdlib and Foundation under
  `/usr/share/swift/usr/lib/swift/linux/`, so the only external libc
  dependency for the Swift binary itself is a Python 3 stdlib for
  interactive `swift repl` (bookworm has libpython3.11; we symlink to
  the libpython3.10 name Ubuntu jammy expects).
- `debian:bookworm-slim` (glibc 2.36) is a strict superset of the glibc
  in jammy (2.35), so jammy-compiled binaries run on bookworm without
  compat shims. The reverse is not always true, which is why `ubuntu:22.04`
  as runtime would risk breakage on any bookworm-compiled binary.

## Ordering of the /usr/local COPYs

Four stages install into `/usr/local`: node, python, ruby, php. We
copy them onto the runtime in that order. Justification:

- Each language uses lang-specific sub-paths for its libraries:
  `lib/node_modules`, `lib/python3.11`, `lib/ruby`, `lib/php`.
  No collisions.
- Binaries are lang-specific under `bin/`: `node`, `npm`, `python3.11`,
  `pip3`, `ruby`, `gem`, `bundle`, `php`, `composer`. No collisions.
- Include headers under `include/` are lang-specific.
- The only overlays are `/usr/local/share/{doc,man,info}/` files with
  identical purpose; later stages replace earlier ones benignly.

If a future upstream image adds a genuinely conflicting file, the
sanity block at the end of the runtime stage (calling
`node --version && python --version && ruby --version && ...`) will
fail loudly and identify the problem.

## Pinning by digest

**base_images_pinned_by_digest: false** in v2 as shipped.

Tags are used (e.g. `node:22-bookworm`) rather than digest pins
(e.g. `node:22-bookworm@sha256:<digest>`). Tags are readable and let
Docker Hub push us security updates within a major-version. The
trade-off is that "same Dockerfile builds the same image" is not
reproducible over time — a rebuild next month may pull a newer patch.

For a reproducible build (paper artifact, publication snapshot), the
pin-by-digest step is:

```bash
for tag in node:22-bookworm python:3.11-bookworm golang:1.24-bookworm \
           ruby:3.3-bookworm rust:1.98-slim-bookworm php:8.3-cli-bookworm \
           eclipse-temurin:21-jdk-jammy swift:6.0-jammy composer:2 \
           mcr.microsoft.com/dotnet/sdk:9.0-bookworm-slim \
           debian:bookworm-slim ; do
  docker pull "$tag" >/dev/null
  docker inspect --format='{{index .RepoDigests 0}}' "$tag"
done
```

Take the output, replace the `FROM` lines in v2 with the digest form,
and commit that as `Dockerfile.replication.v2.pinned`. This is the
recommended path for a paper-quality build.

## What v2 does NOT change vs v1

- Entrypoint script (`replication-entrypoint.sh`) is unchanged and
  reused.
- Language versions match what v1 targeted: Node 22, Python 3.11,
  Go 1.24, Ruby 3.3.8, JDK 21, Kotlin 2.0.21, .NET SDK 9.0, Rust 1.98,
  PHP 8.3, Swift 6.0.
- The Java compilation step still expects pre-vendored Jackson jars
  under `test/vectors/runners/`. v2 does not re-fetch from Maven Central.
- The Swift lane is still SKIPPED on Linux by default (see the smoke
  test SDK_LANES filter). The container ships a working Swift 6.0
  toolchain so the platform guard can be patched off for a Linux run.

## Rollout plan

- v1 remains the shipping Dockerfile until v2 has produced a green
  end-to-end smoke run and a green stage2 matrix on a clean host.
- v2 is dry-parsed via `docker buildx build --check` (see the "Verify"
  section below) before any actual build attempt.
- Once v2 produces a byte-identical `matrix-results.json` to a fresh v1
  build, v1 gets renamed to `Dockerfile.replication.v1.deprecated`
  and v2 gets renamed to `Dockerfile.replication`.

## Verify (dry-run parse, no build)

```bash
docker buildx build \
  --check \
  -f docker/Dockerfile.replication.v2 \
  .
```

`--check` runs Dockerfile linting and the frontend syntax parse without
actually pulling any base images or executing any RUN. Use this before
committing changes to v2.

## Not yet handled (intentional deferrals)

- **Multi-arch (arm64) builds.** v2 does not set explicit `--platform`
  arguments on any stage. The official images we pull are all
  multi-arch, so `docker buildx build --platform=linux/arm64 -f
  Dockerfile.replication.v2 .` should Just Work, but that has not been
  verified. arm64 verification is a follow-up.
- **Image size.** v2 is not size-optimized. The runtime image includes
  full SDKs (not just runtimes) for Java, .NET, Rust, Swift, Go because
  the harness compiles inside the container. A future v3 could split
  "compile" and "runtime" into two stages and produce a much smaller
  runtime image; for now, the whole matrix runs inside one image and
  the size is acceptable (~4-5 GB).
- **Digest pinning** — see the "Pinning by digest" section above.

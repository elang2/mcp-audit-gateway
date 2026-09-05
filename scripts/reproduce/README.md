# Cross-emitter matrix — reproduce from scratch

Deterministically rebuild the ten-SDK cross-emitter conformance / fuzz
harness on a fresh Ubuntu 22.04 x86-64 box.  Every SDK is pinned to the
exact version that produced the published matrix results, so a clean run
here should be byte-identical to the results in `bench/` and
`docs/cross-emitter-matrix/`.

## Prerequisites

- **OS**: Ubuntu 22.04 LTS (jammy), x86-64 is the baseline that produced
  the published matrix. As of 2026-09-03 the installer's baseline
  check is a **soft gate**, not a hard gate. On the baseline host the
  script runs unchanged. On any other Linux host it prints a prominent
  warning listing the SDK version checks most likely to fail, then
  requires an explicit `REPRO_ALLOW_ANY_UBUNTU=1` environment variable
  before it will proceed. See "Running on a non-baseline host" below.
- **Disk**: ~20 GB free.  Rough footprint per SDK:
  Swift ~4 GB, .NET ~1.5 GB, Kotlin ~0.5 GB, Go ~0.5 GB, Rust ~1 GB,
  vendored Maven jars ~50 MB, plus `apt` caches.
- **Privileges**: `sudo` access.  The script uses apt, dpkg, and writes
  into `/usr/local`, `/opt`, `/etc/apt/sources.list.d`.
- **Network**: outbound HTTPS to
  `deb.nodesource.com`, `go.dev`, `packages.microsoft.com`,
  `sh.rustup.rs`, `getcomposer.org`, `repo1.maven.org`,
  `github.com/JetBrains`, `download.swift.org`, and standard Ubuntu
  mirrors.
- **Shell**: `bash` (the script sets `set -Eeuo pipefail`).

## Pinned versions

| Runtime        | Version        | Source                              |
| -------------- | -------------- | ----------------------------------- |
| Node.js        | 22.x           | NodeSource apt repo                 |
| Python         | 3.11 (apt)     | Ubuntu jammy `python3.11`           |
| Go             | 1.24.7         | `go.dev` tarball → `/usr/local/go`  |
| Ruby           | 3.3.8          | `ppa:instructional/ruby-3.3` (fallback: brightbox) |
| OpenJDK        | 21 (headless)  | `openjdk-21-jdk-headless`           |
| Kotlin         | 2.0.21         | JetBrains GitHub release            |
| .NET SDK       | 9.0            | Microsoft `packages-microsoft-prod` |
| Rust           | 1.98.0         | `rustup` (minimal profile)          |
| PHP            | 8.3            | `ppa:ondrej/php`                    |
| Swift          | 5.10.1         | swift.org Ubuntu 22.04 tarball      |

Pinned library versions (installed by the same script):

| Library                                   | Version   | Package manager |
| ----------------------------------------- | --------- | --------------- |
| `rfc8785` (Python JCS)                    | 0.1.4     | pip             |
| `cryptography`                            | 43.0.1    | pip             |
| `pynacl`                                  | 1.5.0     | pip             |
| `ed25519` (Ruby)                          | 1.3.0     | gem             |
| `base64` (Ruby)                           | 0.2.0     | gem             |
| `json-canonicalization` (Ruby)            | 1.0.0     | gem             |
| Jackson (core / annotations / databind)   | 2.16.0    | Maven jars → `/opt/cross-emitter-vendor/jackson-2.16.0` |
| `java-json-canonicalization`              | 1.1       | Maven jar → `/opt/cross-emitter-vendor/json-canonicalization-1.1` |
| `NSec.Cryptography`                       | 24.4.0    | NuGet (on build) |
| `serde_jcs`                               | 0.1.x     | Cargo (on build) |
| `root23/php-json-canonicalization`        | latest    | composer global |

`.NET` and `Rust` deps are resolved lazily on first build, so `dotnet
build` / `cargo build` in the harness will pull them; there is no
per-machine one-time install for those two.

## Usage

```bash
# 1. Install everything (idempotent — safe to re-run):
bash scripts/reproduce/setup.sh

# 2. Pick up PATH exports in your current shell (or open a new one):
source scripts/reproduce/env.sh

# 3. Verify:
bash scripts/reproduce/smoke-test.sh
```

The setup script:

1. Confirms Ubuntu 22.04 x86-64 as a soft check — aborts by default on
   any other host, prints a warning that names the SDK checks likely to
   diverge, and honours `REPRO_ALLOW_ANY_UBUNTU=1` to opt in on non-baseline
   hardware. See "Running on a non-baseline host" below.
2. Installs base apt packages (build tools, curl, gnupg, unzip, …).
3. Writes a managed block into `~/.bashrc` that sources
   `scripts/reproduce/env.sh` — the single source of truth for every
   SDK's env vars. The block is bracketed by
   `# >>> cross-emitter-matrix reproduce (managed) >>>` markers; rerun
   replaces the block in place, never duplicates.
4. Installs each SDK, verifying its version after install.
5. Prints a `SETUP COMPLETE` summary with every installed version.

The smoke test verifies every SDK is on `PATH` at the expected version
**and** compiles/runs a minimal program that canonicalizes
`{"b":1,"a":2}` through that SDK's JCS library.  All ten cells should
emit `{"a":2,"b":1}`.

### Running on a non-baseline host

The published cross-emitter matrix was produced on Ubuntu 22.04 x86-64.
`setup.sh` treats that as the baseline and refuses to proceed on any
other host unless the caller opts in.

To opt in, set `REPRO_ALLOW_ANY_UBUNTU=1` in the environment before
invoking the script:

```bash
REPRO_ALLOW_ANY_UBUNTU=1 bash scripts/reproduce/setup.sh
```

Before the script proceeds it prints a warning that names, one per
line, every SDK version check that pins to Ubuntu 22.04-specific
packages, PPAs, or tarballs. On a non-baseline host the following are
likely to install a divergent SDK patch level or fail outright:

- Node.js 22.x — the NodeSource apt repo carries a Ubuntu 22.04
  (`jammy`) codename; on other releases the setup script it ships may
  not resolve.
- Python 3.11 — `apt install python3.11` lands 3.11 on jammy; on
  Ubuntu 24.04 (`noble`) or 26.04 the default `python3` moves forward
  and the pinned pip wheels (`rfc8785==0.1.4`, `cryptography==43.0.1`,
  `pynacl==1.5.0`) may not have prebuilt wheels for the newer CPython.
- Go 1.24.7 — tarball URL is `linux-amd64`, so non-x86_64
  architectures fail at download.
- Ruby 3.3.8 via rbenv — needs a working `autoconf`, `bison`, and
  `libssl-dev` on the host; the exact package names differ on Debian.
- OpenJDK 21 — `openjdk-21-jdk-headless` is available on jammy,
  noble, and current Debian; older releases (bionic, focal) miss it.
- Kotlin 2.0.21 — the JetBrains GitHub release is a pure-JVM zip and
  works on any host with JDK 21.
- .NET SDK 9.0 — the Microsoft `packages-microsoft-prod.deb` used
  here is the `ubuntu/22.04` variant. On other Debian-family releases
  the correct variant differs.
- Rust 1.98 via rustup — OS-agnostic on any Linux with a `curl` and
  a C toolchain.
- PHP 8.3 — `ppa:ondrej/php` is Ubuntu-only.
- Swift 5.10.1 — the tarball URL is `ubuntu22.04` and pins glibc; on
  a newer Ubuntu (noble+) the newer Swift release must be selected.

On any host that is not Ubuntu 22.04 x86-64, expect some subset of the
21 smoke checks to fail on OS-level version constraints rather than on
the harness itself. Record the resulting SDK versions in your smoke
output so a reviewer can distinguish version-drift failures from real
regressions against the pinned baseline.

The opt-in flag is **not** a bypass for arm64, Windows, or macOS.
Those hosts still fail at every tarball download step and are not
supported.

### env.sh: environment single source of truth

`scripts/reproduce/env.sh` is a checked-in, non-guarded shell file
containing every export the harness needs (`GOROOT`, `KOTLIN_HOME`,
`SWIFT_HOME`, `DOTNET_ROOT`, `CARGO_HOME`, `RBENV_ROOT`,
`CROSS_EMITTER_VENDOR`, and the composed `PATH`). It is sourced by both
the interactive-shell path (via the managed `~/.bashrc` block) and the
non-interactive scripts (`smoke-test.sh` and the matrix runners) so
every shell — script or terminal — sees identical env state.

This replaced an earlier approach that sourced `~/.bashrc` directly.
That earlier approach broke on stock Ubuntu 22.04 because
`/etc/skel/.bashrc` has an interactive-only guard near the top:

```sh
case $- in
    *i*) ;;
      *) return;;
esac
```

Scripts source `~/.bashrc` non-interactively; `$-` lacks `i`, so the
guard returns before the managed PATH block appended below it ever
runs. The observed failure was 11-of-22 smoke checks passing — every
SDK whose home lived under `$HOME/.rbenv`, `/opt/kotlinc`, `/opt/swift`,
`/usr/share/dotnet`, `~/.cargo/bin`, or `~/.config/composer/vendor/bin`
was silently unreachable in each per-SDK subshell. `env.sh` sits
outside `.bashrc`'s guard entirely, so both interactive and
non-interactive shells resolve the same PATH.

Overrides work naturally: exporting `KOTLIN_HOME` or `DOTNET_ROOT`
before sourcing (e.g. to point at an SDKMan-installed candidate or a
per-user `~/.dotnet`) is honoured — every export in `env.sh` uses the
`${VAR:-default}` idiom, so pre-set values win.

## Per-cell reproduction

Once the smoke test is green, reproduce any individual matrix cell with:

```bash
node fuzz-runner.mjs --canonical-form=<form> \
    < <(node generator.mjs <seed> <records>)
```

Where:

- `<form>` — one of `jcs`, `tuple-array`, `rfc8785-strict`, `sort-keys`
  (see `docs/cross-emitter-matrix/forms.md` for the full list).
- `<seed>` — 32-bit unsigned int; the seed is echoed in every run log
  so results are byte-reproducible.
- `<records>` — number of records to feed through the emitter (matrix
  runs use `100000`; smoke runs use `1000`).

Example: reproduce the JCS baseline cell for seed `0xdeadbeef` with
100 000 records:

```bash
node fuzz-runner.mjs --canonical-form=jcs \
    < <(node generator.mjs 0xdeadbeef 100000)
```

Full-matrix reproduction (all ten SDKs × all four forms) is driven by
`scripts/matrix/run-all.sh` — see the matrix README for the sweep
harness.

## Troubleshooting

- **`sudo` prompt loops** — the script calls `sudo -v` once up front to
  cache credentials; if you hit prompt loops, `sudo -k && sudo true`
  before re-running.
- **`add-apt-repository: command not found`** — install
  `software-properties-common` (the script does this in
  `base_packages`, but a partial run may have skipped it).
- **Ruby 3.3 install** — the script uses `rbenv` + `ruby-build` to
  install `3.3.8` directly from the ruby-lang.org tarball. If the
  download fails, retry — a pre-cached copy in
  `~/.rbenv/cache/ruby-3.3.8.tar.gz` is reused on the next run.
- **Swift download slow** — the `.tar.gz` is ~700 MB.  Consider a
  co-located mirror if you're re-provisioning many boxes.
- **`bashrc` block seems wrong** — the managed block is bounded by
  `# >>> cross-emitter-matrix reproduce (managed) >>>` and
  `# <<< cross-emitter-matrix reproduce (managed) <<<`.  Delete
  everything between (inclusive) and re-run `setup.sh` to regenerate.
- **Smoke test reports 22/22 fails or partial pass** — first check
  that `scripts/reproduce/env.sh` exists and is readable. The smoke
  test sources it directly (bypassing `~/.bashrc`'s interactive-only
  guard). If `env.sh` is missing, the harness falls back to the
  compiled-in defaults on lines 128–133 of `smoke-test.sh`, which cover
  the setup.sh install locations but not user overrides.
- **`Kotlin: unresolved reference JsonCanonicalizer`** — `kotlinc`
  does not expand `dir/*.jar` classpath globs (unlike `javac`). The
  smoke test enumerates the vendored jars explicitly for the Kotlin
  cell (see the `KT_CP` construction). If you added new jars to
  `/opt/cross-emitter-vendor/*/`, re-source `env.sh` and re-run.
- **`.NET NSec cell fails with mixed output`** — some `.NET 9.0.x`
  patch levels emit `NETSDK1206` warnings to stdout during `dotnet
  run`. The smoke test now takes the last line of `dotnet run` output
  rather than requiring strict equality against the full stdout, so
  the check is stable across warning noise.

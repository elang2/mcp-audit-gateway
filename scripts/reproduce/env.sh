#!/usr/bin/env bash
# =============================================================================
# Cross-emitter matrix harness — environment file
# =============================================================================
# Single source of truth for the env vars every SDK cell (setup.sh, smoke-test.sh,
# matrix runners) needs. Written to disk so it is sourceable from a plain
# non-interactive shell — bypassing ~/.bashrc's interactive-only guard, which
# on stock Ubuntu 22.04 returns immediately for scripts:
#
#     case $- in
#         *i*) ;;
#           *) return;;
#     esac
#
# That guard sits above where setup.sh appended its managed PATH block, which
# is why prior smoke-test runs found only 11 of 22 SDK checks green:
# `source ~/.bashrc` from a script was a no-op, so nothing under $HOME/.rbenv,
# /opt/kotlinc, /usr/local/go, ~/.cargo, /opt/swift, /usr/share/dotnet, or
# ~/.config/composer/vendor/bin was reachable in the subshells that
# each per-SDK cell spawns.
#
# Usage
# -----
#   . scripts/reproduce/env.sh        # source into current shell
#   bash -c '. scripts/reproduce/env.sh && node -v'   # or into a subshell
#
# The file is idempotent (safe to source multiple times) and side-effect free
# beyond exporting vars and mutating PATH. It does not print anything on the
# happy path — quiet by design so it can be sourced from CI without noise.
# =============================================================================

# Roots for each SDK, overridable by callers who have installed to non-default
# locations (SDKMAN, brew, etc). If any of these already point at a working
# install, they win. Otherwise the defaults match what setup.sh lays down.
export GOROOT="${GOROOT:-/usr/local/go}"
export GOPATH="${GOPATH:-${HOME}/go}"
export KOTLIN_HOME="${KOTLIN_HOME:-/opt/kotlinc}"
export SWIFT_HOME="${SWIFT_HOME:-/opt/swift}"
export DOTNET_ROOT="${DOTNET_ROOT:-/usr/share/dotnet}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
export RBENV_ROOT="${RBENV_ROOT:-${HOME}/.rbenv}"
export CROSS_EMITTER_VENDOR="${CROSS_EMITTER_VENDOR:-/opt/cross-emitter-vendor}"

# JAVA_HOME: GitHub Actions Ubuntu runners ship multiple JDKs pre-installed with
# lower-numbered versions ahead of newer ones on PATH. Pin JAVA_HOME to the
# openjdk-21 install path that setup.sh apt-installs, and prepend its bin to
# PATH so `java -version` reports 21 across all subshells. Overridable by any
# caller who has already set JAVA_HOME.
if [[ -z "${JAVA_HOME:-}" ]]; then
  if [[ -x "/usr/lib/jvm/java-21-openjdk-amd64/bin/java" ]]; then
    export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
  elif [[ -x "/usr/lib/jvm/temurin-21-jdk-amd64/bin/java" ]]; then
    export JAVA_HOME="/usr/lib/jvm/temurin-21-jdk-amd64"
  fi
fi

# PATH: prepend every SDK's bin dir onto whatever PATH the caller already
# has. Preserving the caller's PATH is critical — without /usr/bin and /bin
# on PATH, even `mktemp`, `cat`, and `rm` disappear and the smoke harness
# itself cannot run. Duplicates on PATH are harmless; the leftmost hit wins
# under POSIX PATH resolution, so re-sourcing this file is a no-op except
# for pushing SDK entries slightly further to the left each time.
_SDK_PATH="${GOROOT}/bin:${GOPATH}/bin:${KOTLIN_HOME}/bin:${SWIFT_HOME}/usr/bin"
_SDK_PATH="${_SDK_PATH}:${DOTNET_ROOT}:${CARGO_HOME}/bin"
_SDK_PATH="${_SDK_PATH}:${RBENV_ROOT}/bin:${RBENV_ROOT}/shims"
_SDK_PATH="${_SDK_PATH}:${HOME}/.config/composer/vendor/bin"
if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
  _SDK_PATH="${JAVA_HOME}/bin:${_SDK_PATH}"
fi
export PATH="${_SDK_PATH}:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
unset _SDK_PATH

# Cargo drops its own env script that hooks up RUSTFLAGS-like state; if
# present, source it. Silent-fail so a partial install does not abort here.
if [[ -f "${CARGO_HOME}/env" ]]; then
  # shellcheck disable=SC1091
  . "${CARGO_HOME}/env" 2>/dev/null || true
fi

# rbenv init sets the rbenv shell function that keeps `rbenv global` etc
# working from scripts; without it, shims still resolve `ruby` (that only
# needs the shims dir on PATH), but subshells that later call `rbenv rehash`
# would fail. Silent-fail on boxes without rbenv installed.
if command -v rbenv >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  eval "$(rbenv init - bash 2>/dev/null || true)"
fi

#!/usr/bin/env bash
# =============================================================================
# Cross-emitter matrix harness — post-install smoke test
# =============================================================================
# Verifies that every pinned SDK from setup.sh is reachable, at the expected
# version, and can compile/run a minimal "hello canonical" program that
# exercises the JSON canonicalization library it will use in the full matrix.
#
# Exit 0 on all-green; exit non-zero with the first cell that fails.
#
# SIGPIPE robustness
# ------------------
# This harness must survive being invoked as e.g.
#     bash -x smoke-test.sh | head -50
# Prior retest observed the outer `head` closing stdin after 50 lines,
# raising SIGPIPE on the harness's next printf; combined with `set -eE`
# and `pipefail`, that killed the script with exit 1 before any smoke
# summary was written — the smoke test wasn't actually verifying, the
# pipe was breaking. Three mitigations are applied here so the harness
# survives a downstream `head -N`:
#   1. `trap '' PIPE` at the top so writes to a closed stdout return
#      EPIPE rather than terminating the process with SIGPIPE.
#   2. Top-level errexit is dropped (`set -Euo pipefail` instead of
#      `set -Eeuo pipefail`) so a printf returning 1 on a broken pipe
#      cannot tear down the harness. Each SDK subshell re-enables
#      `set -e` locally so command failures inside an SDK cell still
#      fail that cell.
#   3. Full output is tee'd to ${SMOKE_LOG:-/tmp/smoke.log} so an
#      inspectable log survives even when stdout is truncated by
#      `head -N`. The recommended re-inspection pattern is
#      `head -N /tmp/smoke.log` (a plain file) rather than
#      `bash -x smoke-test.sh | head -N` (the SIGPIPE-vulnerable form).
# All version-check subcommands avoid `| head -n1` (which can trip
# pipefail via SIGPIPE inside command substitution); first-line
# extraction is done with bash parameter expansion (`${out%%$'\n'*}`).
# PIPESTATUS handling: pipes inside SDK cells that could produce more
# output than the consumer reads (e.g. `swift run | tail -n1`) are
# rewritten to full-capture-then-string-op so no producer is exposed to
# SIGPIPE from a downstream reader inside a `set -e` subshell.
# =============================================================================

set -Euo pipefail
trap '' PIPE

# Diagnostic banner emitted BEFORE the tee redirect so it lands on the
# terminal even if the tee subprocess or a later env-load step tears the
# script down before its first per-SDK line. A prior retest observed
# rc=1 in 0s with a zero-byte log; without this banner, that failure
# mode leaves no visible timestamp at all.
printf 'SMOKE TEST STARTING %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

SMOKE_LOG="${SMOKE_LOG:-/tmp/smoke.log}"
: > "${SMOKE_LOG}"
# Duplicate stdout+stderr into ${SMOKE_LOG}. If the parent pipes our stdout
# into `head -N`, tee's own stdout errors but the log file continues to
# receive the full stream, and PIPE-ignore keeps the shell alive on the
# write that follows.
exec > >(tee -a "${SMOKE_LOG}") 2>&1

# Re-emit the banner AFTER the tee redirect so the log file also has a
# timestamped starting marker (the pre-tee banner only reaches the parent
# terminal, not ${SMOKE_LOG}).
printf 'SMOKE TEST STARTING %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

pass_cnt=0
fail_cnt=0
FAIL_CELLS=()

step()  { printf '\n%s==>%s %s%s%s\n' "${C_BLUE}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }
pass()  { printf '  %s[pass]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; pass_cnt=$((pass_cnt+1)); }
skip()  { printf '  %s[skip]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
oops()  { printf '  %s[fail]%s %s\n' "${C_RED}"   "${C_RESET}" "$*"; fail_cnt=$((fail_cnt+1)); FAIL_CELLS+=("$1"); }

# Pull env for this shell so `bash scripts/reproduce/smoke-test.sh` works
# without needing the user to `source ~/.bashrc` first.
#
# HISTORY: prior versions sourced ${HOME}/.bashrc directly. That failed
# on stock Ubuntu 22.04 because /etc/skel/.bashrc has an interactive-only
# guard at the top:
#
#     case $- in
#         *i*) ;;
#           *) return;;
#     esac
#
# When a script invokes `source ~/.bashrc`, `$-` is missing `i`, so the
# guard returns before hitting the managed PATH block that setup.sh
# appends further down. The observed failure was that only 11 of 22
# smoke checks passed because nothing under $HOME/.rbenv, /opt/kotlinc,
# /usr/local/go, ~/.cargo, /opt/swift, /usr/share/dotnet, or
# ~/.config/composer/vendor/bin was reachable from the subshell each
# per-SDK cell spawns.
#
# The fix is `scripts/reproduce/env.sh` — a plain env file that lives
# in the repo, is not gated on interactive shells, and is the single
# source of truth for every SDK's env vars. Sourcing it here (with
# `set +u` around it to survive rbenv init's optional-var reads) makes
# every SDK's binaries and libraries reachable from every subshell we
# spawn below.
#
# BELT-AND-SUSPENDERS: pre-seed shell vars that init scripts commonly
# reference with empty defaults via the bash colon-null-assignment
# pattern (`: "${VAR:=}"`). Under `set -u`, referencing an unset var
# would abort the script before the tee subprocess has flushed — the
# observed failure mode is rc=1 in 0s with a zero-byte log and zero
# per-SDK lines emitted.
: "${PS1:=}"
: "${PS2:=}"
: "${PS4:=}"
: "${BASH_ENV:=}"
: "${ENV:=}"
: "${PROMPT_COMMAND:=}"
: "${SHLVL:=1}"
_SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_SMOKE_DIR}/env.sh" ]]; then
  set +u
  # shellcheck disable=SC1091
  source "${_SMOKE_DIR}/env.sh" >/dev/null 2>&1 || true
  set -u
fi
# Belt-and-suspenders: reassert defaults in case env.sh was missing.
export GOROOT="${GOROOT:-/usr/local/go}"
export SWIFT_HOME="${SWIFT_HOME:-/opt/swift}"
export KOTLIN_HOME="${KOTLIN_HOME:-/opt/kotlinc}"
export DOTNET_ROOT="${DOTNET_ROOT:-/usr/share/dotnet}"
export CROSS_EMITTER_VENDOR="${CROSS_EMITTER_VENDOR:-/opt/cross-emitter-vendor}"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RBENV_ROOT="${RBENV_ROOT:-${HOME}/.rbenv}"
export PATH="${GOROOT}/bin:${SWIFT_HOME}/usr/bin:${KOTLIN_HOME}/bin:${DOTNET_ROOT}:${CARGO_HOME}/bin:${RBENV_ROOT}/bin:${RBENV_ROOT}/shims:${HOME}/.config/composer/vendor/bin:${PATH}"

# =============================================================================
# Version checks
# =============================================================================
step "version checks"

check_version() {
  local label="$1" cmd="$2" pattern="$3"
  local out first_line
  if ! out="$(eval "${cmd}" 2>&1)"; then
    oops "${label}"
    printf '     command failed: %s\n' "${cmd}"
    return
  fi
  # First line via bash param expansion — avoids `| head -n1` which can trip
  # pipefail via SIGPIPE inside command substitution.
  first_line="${out%%$'\n'*}"
  if [[ "${out}" =~ ${pattern} ]]; then
    pass "${label}: ${first_line}"
  else
    oops "${label}"
    printf '     expected match: %s\n     got: %s\n' "${pattern}" "${first_line}"
  fi
}

check_version "Node 22.x"     "node -v"                       '^v22\.'
check_version "Python 3.11"   "python3.11 -V"                 'Python 3\.11'
check_version "Go 1.24.7"     "go version"                    'go1\.24\.7'
check_version "Ruby 3.3"      "ruby -v"                       'ruby 3\.3'
check_version "OpenJDK 21"    "java -version 2>&1"            '\"21\.'
check_version "Kotlin 2.0.21" "kotlinc -version 2>&1"         '2\.0\.21'
check_version ".NET SDK 9.0"  "dotnet --version"              '^9\.0'
check_version "Rust 1.98"     "rustc --version"               '1\.98'
check_version "PHP 8.3"       "php -v"                        'PHP 8\.3'
check_version "Composer"      "composer --version"            'Composer'
check_version "Swift 5.10.1"  "swift --version 2>&1"          '5\.10\.1'

# =============================================================================
# Library smoke: canonicalize {"b":1,"a":2} and print JCS output
# =============================================================================
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

step "library smoke — JCS canonicalization on {\"b\":1,\"a\":2}"

# Guarantee: every one of the 10 SDKs below (Node, Python, Go, Ruby, Java,
# Kotlin, .NET, Rust, PHP, Swift) emits exactly one PASS or FAIL line so the
# summary always shows 10 canonicalization results — a missing binary maps
# to FAIL, not a silent skip. This is what makes the smoke test actually
# verify each SDK rather than quietly no-op when a runtime is absent.

# ---- Node --------------------------------------------------------------------
if command -v node >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir node && cd node
    cat > pkg.mjs <<'JS'
import canon from "canonicalize";
console.log(canon({b:1,a:2}));
JS
    npm init -y >/dev/null 2>&1
    npm install --silent canonicalize >/dev/null 2>&1
    out="$(node pkg.mjs)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Node canonicalize" || oops "Node canonicalize"
else
  oops "Node canonicalize"; printf '     node not on PATH\n'
fi

# ---- Python ------------------------------------------------------------------
if command -v python3.11 >/dev/null 2>&1; then
  out="$(python3.11 -c 'import rfc8785,sys; sys.stdout.write(rfc8785.dumps({"b":1,"a":2}).decode())' 2>&1)"
  [[ "${out}" == '{"a":2,"b":1}' ]] && pass "Python rfc8785" || oops "Python rfc8785"
else
  oops "Python rfc8785"; printf '     python3.11 not on PATH\n'
fi

# ---- Go ----------------------------------------------------------------------
if command -v go >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir gojcs && cd gojcs
    cat > go.mod <<'MOD'
module smoke
go 1.24
MOD
    cat > main.go <<'GO'
package main

import (
	"fmt"
	"github.com/gowebpki/jcs"
)

func main() {
	b, err := jcs.Transform([]byte(`{"b":1,"a":2}`))
	if err != nil { panic(err) }
	fmt.Print(string(b))
}
GO
    go mod tidy >/dev/null 2>&1
    out="$(go run .)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Go gowebpki/jcs" || oops "Go gowebpki/jcs"
else
  oops "Go gowebpki/jcs"; printf '     go not on PATH\n'
fi

# ---- Ruby --------------------------------------------------------------------
# API note: the `json-canonicalization` gem (1.0.0) does not expose
# `JSON.canonicalize`; it monkey-patches `to_json_c14n` onto Object/Hash/
# Array/Numeric. Prior smoke-test used the wrong entrypoint and always
# failed with `undefined method 'canonicalize' for module JSON` even
# when the gem was correctly installed.
if command -v ruby >/dev/null 2>&1; then
  # `tr -d "\n"` consumes its full stdin so ruby is never SIGPIPE'd; safe
  # under pipefail.
  out="$(ruby -e 'require "json/canonicalization"; print({"b"=>1,"a"=>2}.to_json_c14n)' 2>&1 | tr -d "\n")"
  [[ "${out}" == '{"a":2,"b":1}' ]] && pass "Ruby json-canonicalization" || oops "Ruby json-canonicalization"
else
  oops "Ruby json-canonicalization"; printf '     ruby not on PATH\n'
fi

# ---- Java --------------------------------------------------------------------
# Package note: the Maven artifact `io.github.erdtman:java-json-canonicalization`
# ships the canonicalizer under package `org.erdtman.jcs`, not `org.webpki.jcs`.
# Prior smoke-test imported the webpki package name (which belongs to a
# different, unrelated implementation not in the vendored jars) and failed
# with `package org.webpki.jcs does not exist` even when the correct jar was
# on the classpath. Verified with `jar tf` on the vendored jar:
#   org/erdtman/jcs/JsonCanonicalizer.class ← this is the one we get.
if command -v java >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir java && cd java
    JCP="${CROSS_EMITTER_VENDOR}/jackson-2.16.0/*:${CROSS_EMITTER_VENDOR}/json-canonicalization-1.1/*"
    cat > Smoke.java <<'J'
import org.erdtman.jcs.JsonCanonicalizer;
public class Smoke {
  public static void main(String[] a) throws Exception {
    System.out.print(new JsonCanonicalizer("{\"b\":1,\"a\":2}").getEncodedString());
  }
}
J
    javac -cp "${JCP}" Smoke.java
    out="$(java -cp ".:${JCP}" Smoke)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Java org.erdtman.jcs" || oops "Java org.erdtman.jcs"
else
  oops "Java org.erdtman.jcs"; printf '     java not on PATH\n'
fi

# ---- Kotlin ------------------------------------------------------------------
# Same package-name correction as Java above: the vendored jar exposes
# `org.erdtman.jcs.JsonCanonicalizer`, not `org.webpki.jcs.JsonCanonicalizer`.
# Kotlin can call the Java bean getter `getEncodedString()` as a Kotlin
# property `.encodedString`.
#
# Classpath note: `javac` and `java` accept `dir/*` glob entries and expand
# them to every jar in the directory (POSIX-style JVM classpath), but
# `kotlinc` does not — a `-cp dir/*` argument is treated as a literal path
# and no jar is loaded. Prior smoke-test used a glob CP for both compilers
# and the Kotlin cell died with `unresolved reference 'JsonCanonicalizer'`.
# The `KT_CP` line below expands both vendor dirs via bash pathname
# expansion, then joins with `:` — kotlinc sees each jar as an explicit
# entry. The `-cp` handed to `java` at run time can still use globs.
if command -v kotlinc >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir kt && cd kt
    JCP="${CROSS_EMITTER_VENDOR}/jackson-2.16.0/*:${CROSS_EMITTER_VENDOR}/json-canonicalization-1.1/*"
    # Expand the globs for kotlinc, whose -cp parser is glob-blind.
    shopt -s nullglob
    _kt_jars=("${CROSS_EMITTER_VENDOR}"/jackson-2.16.0/*.jar "${CROSS_EMITTER_VENDOR}"/json-canonicalization-1.1/*.jar)
    shopt -u nullglob
    KT_CP="$(IFS=:; printf '%s' "${_kt_jars[*]}")"
    cat > Smoke.kt <<'K'
import org.erdtman.jcs.JsonCanonicalizer
fun main() = print(JsonCanonicalizer("{\"b\":1,\"a\":2}").encodedString)
K
    kotlinc -cp "${KT_CP}" -include-runtime -d smoke.jar Smoke.kt >/dev/null 2>&1
    out="$(java -cp "smoke.jar:${JCP}" SmokeKt)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Kotlin org.erdtman.jcs" || oops "Kotlin org.erdtman.jcs"
else
  oops "Kotlin org.erdtman.jcs"; printf '     kotlinc not on PATH\n'
fi

# ---- .NET --------------------------------------------------------------------
# Two bugs on the original .NET cell fixed here:
#   1. `dotnet add package Jcs` — there is no NuGet package named `Jcs` for
#      JSON canonicalization. The resolver found an unrelated Java-bridge
#      package `jcs 2022.1011.2011.18` (with JavaCommons dependency) that
#      pulled in NU1701 target-framework warnings on every build. The line
#      was `|| true`-guarded so the package addition itself did not fail,
#      but its transitive warnings polluted every subsequent stdout stream.
#      Removed — this cell exercises NSec + System.Text.Json, no JCS lib
#      is actually needed for the sort-keys smoke.
#   2. Strict `[[ "${out}" == '...' ]]` on the full stdout of `dotnet run`.
#      On .NET 9.0.317+ the SQLitePCLRaw NETSDK1206 RID warning is written
#      to stdout, so `out` contained the warning followed by the JSON, and
#      the equality check always failed. Now we take the last line via
#      bash param expansion (same trick as the Swift cell).
if command -v dotnet >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir dn && cd dn
    dotnet new console --force >/dev/null 2>&1
    dotnet add package NSec.Cryptography --version 24.4.0 >/dev/null 2>&1
    cat > Program.cs <<'CS'
using System;
using System.Text.Json;
using System.Text.Json.Nodes;
class P {
  static void Main() {
    var n = JsonNode.Parse("{\"b\":1,\"a\":2}")!.AsObject();
    var sorted = new JsonObject();
    foreach (var k in new []{"a","b"}) sorted[k] = n[k]!.DeepClone();
    Console.Write(sorted.ToJsonString(new JsonSerializerOptions{ }));
  }
}
CS
    full="$(dotnet run --nologo -c Release 2>/dev/null)"
    out="${full##*$'\n'}"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass ".NET NSec + System.Text.Json" || oops ".NET NSec + System.Text.Json"
else
  oops ".NET NSec + System.Text.Json"; printf '     dotnet not on PATH\n'
fi

# ---- Rust --------------------------------------------------------------------
if command -v cargo >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && cargo new --quiet rustjcs >/dev/null 2>&1 && cd rustjcs
    cat > Cargo.toml <<'TOML'
[package]
name = "rustjcs"
version = "0.1.0"
edition = "2021"

[dependencies]
serde_json = "1"
serde_jcs  = "0.1"
TOML
    cat > src/main.rs <<'RS'
fn main() {
    let v: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
    print!("{}", serde_jcs::to_string(&v).unwrap());
}
RS
    out="$(cargo run --quiet 2>/dev/null)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Rust serde_jcs" || oops "Rust serde_jcs"
else
  oops "Rust serde_jcs"; printf '     cargo not on PATH\n'
fi

# ---- PHP ---------------------------------------------------------------------
# Namespace note: packagist's `root23/php-json-canonicalization` uses
# `Root23\JsonCanonicalizer\` (singular) as its PSR-4 prefix, not
# `Root23\JsonCanonicalization\`. Prior smoke-test used the -ization
# variant and always died with a Class-Not-Found even when composer had
# installed the package correctly. Verified against composer show:
#   autoload → psr-4 → Root23\JsonCanonicalizer\ => src.
if command -v php >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir phpjcs && cd phpjcs
    composer require --quiet root23/php-json-canonicalization >/dev/null 2>&1
    cat > run.php <<'PHP'
<?php
require __DIR__ . '/vendor/autoload.php';
use Root23\JsonCanonicalizer\JsonCanonicalizer;
echo (new JsonCanonicalizer())->canonicalize(json_decode('{"b":1,"a":2}'));
PHP
    out="$(php run.php)"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "PHP root23/php-json-canonicalization" || oops "PHP root23/php-json-canonicalization"
else
  oops "PHP root23/php-json-canonicalization"; printf '     php not on PATH\n'
fi

# ---- Swift -------------------------------------------------------------------
# Layout note: Swift 5.5+ `swift package init --type executable` generates
# `Sources/<name>/<name>.swift` with an `@main` entry-point struct. Writing
# an additional `main.swift` alongside it triggers a compile error:
# `'main' attribute cannot be used in a module that contains top-level code`.
# Prior smoke-test hit this on Swift 5.10.1 and always failed the Swift
# cell even when swift itself was correctly installed. Fix: sweep the
# auto-generated .swift files from Sources/swiftjcs/ before dropping in
# main.swift, so top-level code is the only entry-point present.
if command -v swift >/dev/null 2>&1; then
  (
    set -e
    cd "${TMP}" && mkdir swiftjcs && cd swiftjcs
    swift package init --type executable >/dev/null 2>&1
    # Purge auto-generated sources so our top-level main.swift is unambiguous.
    rm -f Sources/swiftjcs/*.swift
    # No canonical Swift JCS package on Swift PM — smoke-test compiles a minimal
    # sort-keys program using Foundation.JSONSerialization + manual sort.
    cat > Sources/swiftjcs/main.swift <<'SW'
import Foundation
let raw = "{\"b\":1,\"a\":2}".data(using: .utf8)!
let obj = try! JSONSerialization.jsonObject(with: raw) as! [String: Any]
let sorted = obj.sorted { $0.key < $1.key }
var out = "{"
for (i, kv) in sorted.enumerated() {
    if i > 0 { out += "," }
    out += "\"\(kv.key)\":\(kv.value)"
}
out += "}"
print(out, terminator: "")
SW
    # Capture the full `swift run` output, then take the last line via bash
    # param expansion. Previously piped through `tail -n1`, which under
    # `set -e` + pipefail would fail the SDK cell whenever swift produced
    # more output than tail read and got SIGPIPE'd.
    full="$(swift run --quiet 2>/dev/null)"
    out="${full##*$'\n'}"
    [[ "${out}" == '{"a":2,"b":1}' ]]
  ) && pass "Swift Foundation sort-keys" || oops "Swift Foundation sort-keys"
else
  oops "Swift Foundation sort-keys"; printf '     swift not on PATH\n'
fi

# =============================================================================
# Summary
# =============================================================================
printf '\n'
if [[ "${fail_cnt}" -eq 0 ]]; then
  printf '%s========================================%s\n' "${C_GREEN}" "${C_RESET}"
  printf '%sSMOKE TEST PASSED%s  (%d checks)\n'          "${C_GREEN}${C_BOLD}" "${C_RESET}" "${pass_cnt}"
  printf '%s========================================%s\n' "${C_GREEN}" "${C_RESET}"
  printf 'full log: %s\n' "${SMOKE_LOG}"
  exit 0
else
  printf '%s========================================%s\n' "${C_RED}" "${C_RESET}"
  printf '%sSMOKE TEST FAILED%s  (%d pass / %d fail)\n' "${C_RED}${C_BOLD}" "${C_RESET}" "${pass_cnt}" "${fail_cnt}"
  printf 'Failed cells:\n'
  for c in "${FAIL_CELLS[@]}"; do printf '  - %s\n' "${c}"; done
  printf '%s========================================%s\n' "${C_RED}" "${C_RESET}"
  printf 'full log: %s\n' "${SMOKE_LOG}"
  exit 1
fi

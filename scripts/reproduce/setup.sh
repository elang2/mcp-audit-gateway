#!/usr/bin/env bash
# =============================================================================
# Cross-emitter matrix harness — fresh Ubuntu 22.04 x86-64 setup
# =============================================================================
# Idempotent installer that pins every SDK to the exact version used to produce
# the published cross-emitter matrix results.  Safe to run multiple times; each
# step checks whether the pinned version is already present before installing.
#
# Target OS  : Ubuntu 22.04 LTS (jammy), x86-64
# Disk req.  : ~20 GB free under /usr/local, /opt, and $HOME
# Privileges : sudo required for apt/dpkg and /usr/local writes
#
# Usage      : bash scripts/reproduce/setup.sh
# Verify     : bash scripts/reproduce/smoke-test.sh
# =============================================================================

set -Eeuo pipefail

# ---- Pinned versions -------------------------------------------------------
NODE_MAJOR="22"
PYTHON_APT_VER="3.11"
PY_RFC8785="0.1.4"
PY_CRYPTOGRAPHY="43.0.1"
PY_PYNACL="1.5.0"
GO_VERSION="1.24.7"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
RUBY_APT_MAJOR="3.3"           # Ubuntu 22.04 ships 3.0; use ppa:instructional/ruby-3.3 fallback
RUBY_VERSION_PIN="3.3.8"
GEM_ED25519="1.3.0"
GEM_BASE64="0.2.0"
GEM_JSON_CANON="1.0.0"
JAVA_MAJOR="21"
JACKSON_VERSION="2.16.0"
JSON_CANON_JAR_VERSION="1.1"
KOTLIN_VERSION="2.0.21"
DOTNET_MAJOR="9.0"
NSEC_VERSION="24.4.0"
RUST_TOOLCHAIN="1.98.0"
PHP_APT_VER="8.3"
COMPOSER_INSTALLER_SHA_URL="https://composer.github.io/installer.sig"
PHP_JSON_CANON_PKG="root23/php-json-canonicalization"
SWIFT_VERSION="5.10.1"
SWIFT_UBUNTU_TAG="ubuntu22.04"
SWIFT_TARBALL="swift-${SWIFT_VERSION}-RELEASE-${SWIFT_UBUNTU_TAG}.tar.gz"
SWIFT_URL="https://download.swift.org/swift-${SWIFT_VERSION}-release/${SWIFT_UBUNTU_TAG//./}/swift-${SWIFT_VERSION}-RELEASE/${SWIFT_TARBALL}"

# ---- Install roots ---------------------------------------------------------
GO_ROOT="/usr/local/go"
KOTLIN_ROOT="/opt/kotlinc"
SWIFT_ROOT="/opt/swift"
VENDOR_DIR="/opt/cross-emitter-vendor"
JACKSON_DIR="${VENDOR_DIR}/jackson-${JACKSON_VERSION}"
JSON_CANON_JAR_DIR="${VENDOR_DIR}/json-canonicalization-${JSON_CANON_JAR_VERSION}"
CARGO_HOME_DEFAULT="${HOME}/.cargo"
RUSTUP_HOME_DEFAULT="${HOME}/.rustup"

# ---- Bash rc block markers -------------------------------------------------
BASHRC="${HOME}/.bashrc"
RC_MARK_BEGIN="# >>> cross-emitter-matrix reproduce (managed) >>>"
RC_MARK_END="# <<< cross-emitter-matrix reproduce (managed) <<<"

# ---- Terminal helpers ------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

log()   { printf '%s[setup]%s %s\n' "${C_BLUE}"  "${C_RESET}" "$*"; }
ok()    { printf '%s[ ok ]%s %s\n'  "${C_GREEN}" "${C_RESET}" "$*"; }
warn()  { printf '%s[warn]%s %s\n'  "${C_YELLOW}" "${C_RESET}" "$*"; }
fail()  { printf '%s[fail]%s %s\n'  "${C_RED}"   "${C_RESET}" "$*" >&2; exit 1; }
step()  { printf '\n%s==>%s %s%s%s\n' "${C_BLUE}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }

on_err() {
  local ec=$?
  local ln=${BASH_LINENO[0]:-?}
  fail "aborted at line ${ln} (exit ${ec}); previous command: ${BASH_COMMAND}"
}
trap on_err ERR

# ---- Preflight -------------------------------------------------------------
# The published cross-emitter matrix was produced on Ubuntu 22.04 x86-64.
# Historically this preflight was a HARD gate that aborted on any other
# host. Starting 2026-09-03 it is a SOFT gate:
#
#   - On Ubuntu 22.04 x86-64 the install runs unchanged.
#   - On any other Linux host (different Ubuntu release, Debian, other
#     x86-64 distros with apt) the script prints a prominent warning
#     listing the SDK version checks most likely to disagree, then
#     requires the caller to opt in with REPRO_ALLOW_ANY_UBUNTU=1 in
#     the environment before it will proceed.
#   - On architectures other than x86-64 the tarball URLs pinned above
#     do not have a valid file, so this remains a hard fail unless the
#     override flag is set — with the flag the script continues but is
#     essentially guaranteed to fail at Go / Swift / .NET download.
#
# The soft gate exists so that reproducibility reviewers who cannot
# provision a 22.04 box (e.g. AEC hardware, ephemeral CI images) can
# still drive the harness to the point where per-SDK versions diverge
# from the pinned set, get a legible failure, and record the delta.
require_ubuntu_2204() {
  if ! command -v lsb_release >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      ${SUDO:-sudo} apt-get update -y >/dev/null 2>&1 || true
      ${SUDO:-sudo} apt-get install -y lsb-release >/dev/null 2>&1 || true
    fi
  fi
  local id rel arch
  id="$(lsb_release -is 2>/dev/null || echo unknown)"
  rel="$(lsb_release -rs 2>/dev/null || echo unknown)"
  arch="$(uname -m)"
  if [[ "${id}" == "Ubuntu" && "${rel}" == "22.04" && "${arch}" == "x86_64" ]]; then
    ok "Ubuntu ${rel} x86_64 confirmed (published matrix baseline)"
    return 0
  fi
  # Non-baseline host. Emit a prominent warning listing every SDK check
  # that pins to an apt-repo or tarball that assumes Ubuntu 22.04
  # x86-64, then honour REPRO_ALLOW_ANY_UBUNTU=1 as the opt-in.
  printf '\n%s%s================================================================%s\n' \
    "${C_YELLOW}" "${C_BOLD}" "${C_RESET}"
  printf '%s%sNON-BASELINE HOST DETECTED%s\n' \
    "${C_YELLOW}" "${C_BOLD}" "${C_RESET}"
  printf '%s================================================================%s\n' \
    "${C_YELLOW}" "${C_RESET}"
  printf '  Detected : %s %s (%s)\n' "${id}" "${rel}" "${arch}"
  printf '  Expected : Ubuntu 22.04 (x86_64)\n\n'
  printf '  The published cross-emitter matrix was produced on the\n'
  printf '  baseline above. On this host the following SDK version\n'
  printf '  checks pin to Ubuntu 22.04-specific packages / tarballs and\n'
  printf '  are LIKELY to fail (or install a divergent version):\n\n'
  printf '    - Node.js %s.x        (NodeSource apt repo -- needs jammy)\n'   "${NODE_MAJOR}"
  printf '    - Python %s          (apt: python%s -- jammy default)\n' \
    "${PYTHON_APT_VER}" "${PYTHON_APT_VER}"
  printf '    - Go %s          (tarball for linux-amd64 -- arch pinned)\n' "${GO_VERSION}"
  printf '    - Ruby %s          (rbenv build; needs Ubuntu build deps)\n' "${RUBY_VERSION_PIN}"
  printf '    - OpenJDK %s          (apt: openjdk-%s-jdk-headless)\n' \
    "${JAVA_MAJOR}" "${JAVA_MAJOR}"
  printf '    - Kotlin %s        (JetBrains GitHub zip -- OS-agnostic)\n' "${KOTLIN_VERSION}"
  printf '    - .NET SDK %s        (Microsoft repo for ubuntu/22.04)\n' "${DOTNET_MAJOR}"
  printf '    - Rust %s        (rustup default -- OS-agnostic)\n' "${RUST_TOOLCHAIN}"
  printf '    - PHP %s          (ppa:ondrej/php -- Ubuntu PPA only)\n' "${PHP_APT_VER}"
  printf '    - Swift %s        (%s tarball -- OS + arch pinned)\n' \
    "${SWIFT_VERSION}" "${SWIFT_UBUNTU_TAG}"
  printf '\n'
  printf '  Non-Ubuntu hosts (Debian, RHEL, macOS, ...) will fail the\n'
  printf '  apt/dpkg-based steps outright. Non-22.04 Ubuntu hosts may\n'
  printf '  install different SDK patch levels than the published matrix.\n'
  printf '  Non-x86_64 architectures will fail at every tarball download.\n\n'
  if [[ "${REPRO_ALLOW_ANY_UBUNTU:-}" == "1" ]]; then
    printf '  REPRO_ALLOW_ANY_UBUNTU=1 set -- proceeding at your own risk.\n'
    printf '  Record the resulting SDK versions in your smoke output so\n'
    printf '  reviewers can distinguish version-drift failures from real\n'
    printf '  regressions against the pinned baseline.\n\n'
    warn "continuing on non-baseline host at caller request"
    return 0
  fi
  printf '  To proceed anyway (e.g. reviewer hardware, CI image), re-run\n'
  printf '  with the opt-in flag:\n\n'
  printf '      REPRO_ALLOW_ANY_UBUNTU=1 bash scripts/reproduce/setup.sh\n\n'
  fail "non-baseline host and REPRO_ALLOW_ANY_UBUNTU not set; refusing to proceed"
}

require_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    sudo -v || fail "sudo authentication required"
  else
    fail "root or sudo is required"
  fi
  export SUDO
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get install -y --no-install-recommends "$@"
}

apt_refresh_once() {
  if [[ -z "${_APT_REFRESHED:-}" ]]; then
    ${SUDO} apt-get update -y
    _APT_REFRESHED=1
  fi
}

base_packages() {
  step "installing base packages"
  apt_refresh_once
  apt_install \
    ca-certificates curl wget gnupg lsb-release software-properties-common \
    build-essential pkg-config git unzip zip xz-utils tar jq \
    apt-transport-https libssl-dev libffi-dev zlib1g-dev \
    libncurses5 libpython3-stdlib libtinfo5 libxml2 \
    libcurl4-openssl-dev libedit2 libgcc-11-dev libsqlite3-0 \
    libstdc++-11-dev libz3-dev
  ok "base packages present"
}

# ---- bashrc block ----------------------------------------------------------
# The managed block sources scripts/reproduce/env.sh — the single source of
# truth for every SDK's env vars. env.sh is a plain non-guarded shell file
# checked into the repo, sourceable from both interactive shells (via this
# bashrc block) and non-interactive scripts (like smoke-test.sh), which
# bypasses the interactive-only guard at the top of stock Ubuntu 22.04
# ~/.bashrc that used to prevent smoke-test from seeing this block.
write_bashrc_block() {
  step "updating ${BASHRC} PATH block"
  touch "${BASHRC}"
  local tmp env_sh
  tmp="$(mktemp)"
  # Resolve the absolute path to env.sh so the bashrc line does not depend
  # on any particular working directory when re-sourced.
  env_sh="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
  # remove any prior managed block
  awk -v b="${RC_MARK_BEGIN}" -v e="${RC_MARK_END}" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "${BASHRC}" > "${tmp}"
  {
    cat "${tmp}"
    printf '\n%s\n' "${RC_MARK_BEGIN}"
    printf '# Managed by scripts/reproduce/setup.sh — do not hand-edit inside this block.\n'
    printf '# Sources the checked-in env file so interactive shells see the same PATH\n'
    printf '# as the reproduce scripts (setup.sh, smoke-test.sh, matrix runners).\n'
    printf 'if [ -f "%s" ]; then . "%s"; fi\n' "${env_sh}" "${env_sh}"
    printf '%s\n' "${RC_MARK_END}"
  } > "${BASHRC}.tmp"
  mv "${BASHRC}.tmp" "${BASHRC}"
  rm -f "${tmp}"
  ok "bashrc block written (sources ${env_sh})"
}

apply_env_current_shell() {
  # Make the same exports visible inside this running script (and inherited
  # by any child processes we spawn for verification).
  export GOROOT="/usr/local/go"
  export GOPATH="${HOME}/go"
  export KOTLIN_HOME="/opt/kotlinc"
  export SWIFT_HOME="/opt/swift"
  export CARGO_HOME="${HOME}/.cargo"
  export RUSTUP_HOME="${HOME}/.rustup"
  export DOTNET_ROOT="/usr/share/dotnet"
  export DOTNET_CLI_TELEMETRY_OPTOUT=1
  export CROSS_EMITTER_VENDOR="${VENDOR_DIR}"
  PATH="${GOROOT}/bin:${GOPATH}/bin:${KOTLIN_HOME}/bin:${SWIFT_HOME}/usr/bin:${CARGO_HOME}/bin:${DOTNET_ROOT}:${HOME}/.config/composer/vendor/bin:${PATH}"
  export PATH
  # Cargo env if already present
  [[ -f "${CARGO_HOME}/env" ]] && . "${CARGO_HOME}/env" || true
}

# =============================================================================
# 1. Node.js 22.x (NodeSource)
# =============================================================================
install_node() {
  step "Node.js ${NODE_MAJOR}.x"
  if command -v node >/dev/null 2>&1 && node -v | grep -qE "^v${NODE_MAJOR}\."; then
    ok "Node $(node -v) already installed"
    return
  fi
  # When SUDO="" (running as root, e.g. inside a Docker container), the literal
  # expansion "${SUDO} -E bash -" becomes "-E bash -", and the shell tries to
  # execute "-E" as a command. Branch on SUDO so both root and non-root work.
  if [[ -z "${SUDO}" ]]; then
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  else
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | ${SUDO} -E bash -
  fi
  apt_install nodejs
  node -v | grep -qE "^v${NODE_MAJOR}\." || fail "Node install did not yield v${NODE_MAJOR}.x"
  ok "Node $(node -v), npm $(npm -v)"
}

# =============================================================================
# 2. Python 3.11 + pinned pip deps
# =============================================================================
install_python() {
  step "Python ${PYTHON_APT_VER} + pip deps"
  apt_refresh_once
  apt_install "python${PYTHON_APT_VER}" "python${PYTHON_APT_VER}-venv" "python${PYTHON_APT_VER}-dev" python3-pip
  command -v "python${PYTHON_APT_VER}" >/dev/null || fail "python${PYTHON_APT_VER} not on PATH"
  "python${PYTHON_APT_VER}" -m pip install --upgrade --quiet pip
  "python${PYTHON_APT_VER}" -m pip install --quiet \
    "rfc8785==${PY_RFC8785}" \
    "cryptography==${PY_CRYPTOGRAPHY}" \
    "pynacl==${PY_PYNACL}"
  "python${PYTHON_APT_VER}" - <<'PY'
import rfc8785, cryptography, nacl
print("rfc8785", rfc8785.__version__ if hasattr(rfc8785, "__version__") else "ok")
print("cryptography", cryptography.__version__)
print("pynacl", nacl.__version__)
PY
  ok "Python $("python${PYTHON_APT_VER}" -V) + pinned deps installed"
}

# =============================================================================
# 3. Go 1.24.7 (tarball to /usr/local/go)
# =============================================================================
install_go() {
  step "Go ${GO_VERSION}"
  if [[ -x "${GO_ROOT}/bin/go" ]] && "${GO_ROOT}/bin/go" version | grep -q "go${GO_VERSION}"; then
    ok "Go $(${GO_ROOT}/bin/go version) already installed"
    return
  fi
  local tmpdir; tmpdir="$(mktemp -d)"
  ( cd "${tmpdir}" && curl -fsSLO "${GO_URL}" )
  ${SUDO} rm -rf "${GO_ROOT}"
  ${SUDO} tar -C /usr/local -xzf "${tmpdir}/${GO_TARBALL}"
  rm -rf "${tmpdir}"
  "${GO_ROOT}/bin/go" version | grep -q "go${GO_VERSION}" || fail "Go install did not yield ${GO_VERSION}"
  ok "$(${GO_ROOT}/bin/go version)"
}

# =============================================================================
# 4. Ruby 3.3.8 + gems (via rbenv + ruby-build; PPA-independent)
# =============================================================================
install_ruby() {
  log "Installing Ruby 3.3.8 via rbenv..."
  export RBENV_ROOT="${HOME}/.rbenv"
  export PATH="${RBENV_ROOT}/bin:${RBENV_ROOT}/shims:${PATH}"
  if [[ ! -d "${RBENV_ROOT}" ]]; then
    git clone --depth=1 https://github.com/rbenv/rbenv.git "${RBENV_ROOT}"
    mkdir -p "${RBENV_ROOT}/plugins"
    git clone --depth=1 https://github.com/rbenv/ruby-build.git "${RBENV_ROOT}/plugins/ruby-build"
  fi
  # Install Ruby build deps
  ${SUDO} apt-get install -y --no-install-recommends \
    autoconf bison patch build-essential rustc libssl-dev libyaml-dev libreadline6-dev \
    zlib1g-dev libgmp-dev libncurses5-dev libffi-dev libgdbm6 libgdbm-dev libdb-dev uuid-dev

  # Pre-download the Ruby tarball into ruby-build's cache with retries. ruby-build's
  # own download path is a single-shot curl that has produced transient TLS/DNS
  # failures against cache.ruby-lang.org. By seeding RUBY_BUILD_CACHE_PATH with a
  # retried download, ruby-build reuses the cached file and its bundled SHA256
  # verification runs against it before compilation begins.
  local ruby_cache="${RBENV_ROOT}/cache"
  local ruby_tarball="ruby-${RUBY_VERSION_PIN}.tar.gz"
  local ruby_minor="${RUBY_VERSION_PIN%.*}"
  local ruby_url="https://cache.ruby-lang.org/pub/ruby/${ruby_minor}/${ruby_tarball}"
  export RUBY_BUILD_CACHE_PATH="${ruby_cache}"
  mkdir -p "${ruby_cache}"
  if [[ ! -f "${ruby_cache}/${ruby_tarball}" ]]; then
    log "Fetching ${ruby_tarball} with retry (3 attempts, 5s delay, 60s cap)..."
    if ! curl --fail --location --silent --show-error \
              --retry 3 --retry-delay 5 --retry-max-time 60 \
              --connect-timeout 15 \
              -o "${ruby_cache}/${ruby_tarball}.part" \
              "${ruby_url}"; then
      rm -f "${ruby_cache}/${ruby_tarball}.part"
      warn "pre-download of ${ruby_tarball} failed; falling back to ruby-build's own fetch"
    else
      mv "${ruby_cache}/${ruby_tarball}.part" "${ruby_cache}/${ruby_tarball}"
    fi

    # Verify the pre-downloaded tarball against ruby-build's authoritative SHA256.
    # ruby-build definition files encode the checksum as a URL fragment
    # (e.g. https://...ruby-3.3.8.tar.gz#<sha256>). If we can locate it we verify
    # up front; otherwise we defer to ruby-build's own post-download verification.
    local def_file="${RBENV_ROOT}/plugins/ruby-build/share/ruby-build/${RUBY_VERSION_PIN}"
    if [[ -f "${ruby_cache}/${ruby_tarball}" && -f "${def_file}" ]]; then
      local expected_sha actual_sha
      expected_sha="$(grep -oE "ruby-${RUBY_VERSION_PIN}\.tar\.gz#[0-9a-f]{64}" "${def_file}" | head -n1 | cut -d'#' -f2 || true)"
      if [[ -n "${expected_sha}" ]]; then
        actual_sha="$(sha256sum "${ruby_cache}/${ruby_tarball}" | awk '{print $1}')"
        if [[ "${expected_sha}" != "${actual_sha}" ]]; then
          warn "SHA256 mismatch on pre-downloaded ${ruby_tarball} (expected ${expected_sha}, got ${actual_sha}); removing so ruby-build can retry"
          rm -f "${ruby_cache}/${ruby_tarball}"
        else
          ok "pre-downloaded ${ruby_tarball} matches ruby-build SHA256"
        fi
      fi
    fi
  fi

  rbenv install -s "${RUBY_VERSION_PIN}"
  rbenv global "${RUBY_VERSION_PIN}"
  rbenv rehash
  ruby --version
  gem install --no-document ed25519 -v "${GEM_ED25519}"
  gem install --no-document base64 -v "${GEM_BASE64}"
  gem install --no-document json-canonicalization -v "${GEM_JSON_CANON}"
}

# =============================================================================
# 5. OpenJDK 21 + Jackson jars + json-canonicalization jar
# =============================================================================
install_java() {
  step "OpenJDK ${JAVA_MAJOR} + vendored jars"
  apt_install "openjdk-${JAVA_MAJOR}-jdk-headless"
  # GitHub Actions runners ship multiple JDKs pre-installed with lower-numbered
  # versions ahead of newer ones on PATH. Explicitly select the JDK we just
  # apt-installed by setting JAVA_HOME + prepending its bin/ before the check.
  local java_home
  java_home="$(dirname "$(dirname "$(readlink -f "$(command -v update-alternatives)")")")"
  # Prefer the canonical apt install path
  if [[ -x "/usr/lib/jvm/java-${JAVA_MAJOR}-openjdk-amd64/bin/java" ]]; then
    export JAVA_HOME="/usr/lib/jvm/java-${JAVA_MAJOR}-openjdk-amd64"
  elif [[ -x "/usr/lib/jvm/temurin-${JAVA_MAJOR}-jdk-amd64/bin/java" ]]; then
    export JAVA_HOME="/usr/lib/jvm/temurin-${JAVA_MAJOR}-jdk-amd64"
  else
    JAVA_HOME="$(find /usr/lib/jvm -maxdepth 2 -type d -name "*${JAVA_MAJOR}*openjdk*" | head -n1)"
    [[ -n "${JAVA_HOME}" && -x "${JAVA_HOME}/bin/java" ]] || fail "cannot locate installed JDK ${JAVA_MAJOR}"
    export JAVA_HOME
  fi
  export PATH="${JAVA_HOME}/bin:${PATH}"
  # Also register with update-alternatives so subsequent shells see it too
  ${SUDO} update-alternatives --set java "${JAVA_HOME}/bin/java" 2>/dev/null || true
  ${SUDO} update-alternatives --set javac "${JAVA_HOME}/bin/javac" 2>/dev/null || true
  java -version 2>&1 | grep -qE "\"${JAVA_MAJOR}(\.|\+)" || fail "Java ${JAVA_MAJOR} not active (java -version: $(java -version 2>&1 | head -n1))"
  ${SUDO} mkdir -p "${JACKSON_DIR}" "${JSON_CANON_JAR_DIR}"
  local jackson_base="https://repo1.maven.org/maven2/com/fasterxml/jackson"
  local jars=(
    "${jackson_base}/core/jackson-core/${JACKSON_VERSION}/jackson-core-${JACKSON_VERSION}.jar"
    "${jackson_base}/core/jackson-annotations/${JACKSON_VERSION}/jackson-annotations-${JACKSON_VERSION}.jar"
    "${jackson_base}/core/jackson-databind/${JACKSON_VERSION}/jackson-databind-${JACKSON_VERSION}.jar"
  )
  for url in "${jars[@]}"; do
    local out="${JACKSON_DIR}/$(basename "${url}")"
    if [[ ! -f "${out}" ]]; then
      ${SUDO} curl -fsSL -o "${out}" "${url}"
    fi
  done
  # json-canonicalization jar (erdtman/java-json-canonicalization publishes via Maven Central)
  local jc_url="https://repo1.maven.org/maven2/io/github/erdtman/java-json-canonicalization/${JSON_CANON_JAR_VERSION}/java-json-canonicalization-${JSON_CANON_JAR_VERSION}.jar"
  local jc_out="${JSON_CANON_JAR_DIR}/java-json-canonicalization-${JSON_CANON_JAR_VERSION}.jar"
  if [[ ! -f "${jc_out}" ]]; then
    ${SUDO} curl -fsSL -o "${jc_out}" "${jc_url}"
  fi
  ok "Java $(java -version 2>&1 | head -n1) + jars in ${VENDOR_DIR}"
}

# =============================================================================
# 6. Kotlin 2.0.21 (GitHub release; SDKMAN not required)
# =============================================================================
install_kotlin() {
  step "Kotlin ${KOTLIN_VERSION}"
  if [[ -x "${KOTLIN_ROOT}/bin/kotlinc" ]] && "${KOTLIN_ROOT}/bin/kotlinc" -version 2>&1 | grep -q "${KOTLIN_VERSION}"; then
    ok "Kotlin ${KOTLIN_VERSION} already installed"
    return
  fi
  local tmpdir; tmpdir="$(mktemp -d)"
  local url="https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip"
  ( cd "${tmpdir}" && curl -fsSLO "${url}" )
  ${SUDO} rm -rf "${KOTLIN_ROOT}"
  ${SUDO} unzip -q "${tmpdir}/kotlin-compiler-${KOTLIN_VERSION}.zip" -d /opt/
  # extracts as /opt/kotlinc — verify path
  [[ -x "${KOTLIN_ROOT}/bin/kotlinc" ]] || fail "kotlinc not at ${KOTLIN_ROOT}/bin/kotlinc"
  rm -rf "${tmpdir}"
  "${KOTLIN_ROOT}/bin/kotlinc" -version 2>&1 | grep -q "${KOTLIN_VERSION}" || fail "Kotlin version mismatch"
  ok "$(${KOTLIN_ROOT}/bin/kotlinc -version 2>&1 | head -n1)"
}

# =============================================================================
# 7. .NET SDK 9.0 (Microsoft package repo)
# =============================================================================
install_dotnet() {
  step ".NET SDK ${DOTNET_MAJOR}"
  if command -v dotnet >/dev/null && dotnet --list-sdks | grep -q "^${DOTNET_MAJOR}\."; then
    ok "$(dotnet --version) already installed"
    return
  fi
  local ms_prod="/etc/apt/sources.list.d/microsoft-prod.list"
  if [[ ! -f "${ms_prod}" ]]; then
    local tmp; tmp="$(mktemp -d)"
    ( cd "${tmp}" && curl -fsSLO https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb )
    ${SUDO} dpkg -i "${tmp}/packages-microsoft-prod.deb"
    rm -rf "${tmp}"
    _APT_REFRESHED=""
  fi
  apt_refresh_once
  apt_install "dotnet-sdk-${DOTNET_MAJOR}"
  dotnet --list-sdks | grep -q "^${DOTNET_MAJOR}\." || fail ".NET ${DOTNET_MAJOR} SDK not installed"
  ok ".NET SDK $(dotnet --version)"
}

# =============================================================================
# 8. Rust 1.98 (rustup)
# =============================================================================
install_rust() {
  step "Rust ${RUST_TOOLCHAIN}"
  if [[ -x "${CARGO_HOME_DEFAULT}/bin/rustc" ]] && "${CARGO_HOME_DEFAULT}/bin/rustc" --version | grep -q "${RUST_TOOLCHAIN%%.*}"; then
    "${CARGO_HOME_DEFAULT}/bin/rustup" toolchain install "${RUST_TOOLCHAIN}" --profile minimal
    "${CARGO_HOME_DEFAULT}/bin/rustup" default "${RUST_TOOLCHAIN}"
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | RUSTUP_HOME="${RUSTUP_HOME_DEFAULT}" CARGO_HOME="${CARGO_HOME_DEFAULT}" \
        sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}" --profile minimal
  fi
  # shellcheck disable=SC1091
  . "${CARGO_HOME_DEFAULT}/env"
  rustc --version | grep -q "${RUST_TOOLCHAIN}" || fail "rustc not ${RUST_TOOLCHAIN}"
  ok "$(rustc --version) / $(cargo --version)"
}

# =============================================================================
# 9. PHP 8.3 (ondrej PPA) + composer + json-canonicalization
# =============================================================================
install_php() {
  step "PHP ${PHP_APT_VER} + composer"
  ${SUDO} add-apt-repository -y ppa:ondrej/php
  ${SUDO} apt-get update -y
  apt_install "php${PHP_APT_VER}" "php${PHP_APT_VER}-cli" "php${PHP_APT_VER}-mbstring" \
              "php${PHP_APT_VER}-xml" "php${PHP_APT_VER}-curl" unzip
  ${SUDO} update-alternatives --set php "/usr/bin/php${PHP_APT_VER}" || true
  php -v | grep -qE "PHP ${PHP_APT_VER//./\\.}\." || fail "PHP ${PHP_APT_VER} not active"

  # Composer installer with signature verification
  if ! command -v composer >/dev/null 2>&1; then
    local exp actual
    exp="$(curl -fsSL "${COMPOSER_INSTALLER_SHA_URL}")"
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    actual="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"
    if [[ "${exp}" != "${actual}" ]]; then
      rm -f composer-setup.php
      fail "composer installer signature mismatch"
    fi
    ${SUDO} php composer-setup.php --install-dir=/usr/local/bin --filename=composer --quiet
    rm -f composer-setup.php
  fi
  composer --version | grep -q "Composer" || fail "composer not on PATH"

  # Global install of the JCS library so any Composer project can require it.
  mkdir -p "${HOME}/.config/composer"
  composer global require --quiet "${PHP_JSON_CANON_PKG}"
  ok "$(php -v | head -n1) + composer $(composer --version | awk '{print $3}')"
}

# =============================================================================
# 10. Swift 5.10.1 (Ubuntu 22.04 tarball)
# =============================================================================
install_swift() {
  step "Swift ${SWIFT_VERSION}"
  if [[ -x "${SWIFT_ROOT}/usr/bin/swift" ]] && "${SWIFT_ROOT}/usr/bin/swift" --version 2>&1 | grep -q "${SWIFT_VERSION}"; then
    ok "Swift ${SWIFT_VERSION} already installed"
    return
  fi
  apt_install libpython3-stdlib libxml2 libedit2 libsqlite3-0 libz3-dev libtinfo5 libncurses5
  local tmpdir; tmpdir="$(mktemp -d)"
  ( cd "${tmpdir}" && curl -fsSLO "${SWIFT_URL}" )
  ${SUDO} rm -rf "${SWIFT_ROOT}"
  ${SUDO} mkdir -p "${SWIFT_ROOT}"
  ${SUDO} tar -C "${SWIFT_ROOT}" --strip-components=1 -xzf "${tmpdir}/${SWIFT_TARBALL}"
  rm -rf "${tmpdir}"
  "${SWIFT_ROOT}/usr/bin/swift" --version 2>&1 | grep -q "${SWIFT_VERSION}" || fail "Swift ${SWIFT_VERSION} did not install"
  ok "$(${SWIFT_ROOT}/usr/bin/swift --version 2>&1 | head -n1)"
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
  printf '\n%s========================================%s\n' "${C_GREEN}" "${C_RESET}"
  printf '%sSETUP COMPLETE%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
  printf '%s========================================%s\n' "${C_GREEN}" "${C_RESET}"
  printf '  Node.js    : %s\n' "$(node -v 2>/dev/null || echo missing)"
  printf '  npm        : %s\n' "$(npm -v 2>/dev/null || echo missing)"
  printf '  Python     : %s\n' "$(python${PYTHON_APT_VER} -V 2>/dev/null || echo missing)"
  printf '  Go         : %s\n' "$(${GO_ROOT}/bin/go version 2>/dev/null || echo missing)"
  printf '  Ruby       : %s\n' "$(ruby -v 2>/dev/null || echo missing)"
  printf '  Java       : %s\n' "$(java -version 2>&1 | head -n1 || echo missing)"
  printf '  Kotlin     : %s\n' "$(${KOTLIN_ROOT}/bin/kotlinc -version 2>&1 | head -n1 || echo missing)"
  printf '  .NET SDK   : %s\n' "$(dotnet --version 2>/dev/null || echo missing)"
  printf '  Rust       : %s\n' "$(rustc --version 2>/dev/null || echo missing)"
  printf '  Cargo      : %s\n' "$(cargo --version 2>/dev/null || echo missing)"
  printf '  PHP        : %s\n' "$(php -v 2>/dev/null | head -n1 || echo missing)"
  printf '  Composer   : %s\n' "$(composer --version 2>/dev/null | head -n1 || echo missing)"
  printf '  Swift      : %s\n' "$(${SWIFT_ROOT}/usr/bin/swift --version 2>&1 | head -n1 || echo missing)"
  printf '\n  Vendor dir : %s\n' "${VENDOR_DIR}"
  printf '  Jackson jars in %s\n' "${JACKSON_DIR}"
  printf '  JCS jar     in %s\n' "${JSON_CANON_JAR_DIR}"
  printf '\n  Open a new shell (or `source ~/.bashrc`) to pick up PATH changes.\n'
  printf '  Next step:  bash scripts/reproduce/smoke-test.sh\n\n'
}

main() {
  require_ubuntu_2204
  require_sudo
  base_packages
  write_bashrc_block
  apply_env_current_shell

  install_node
  install_python
  install_go
  install_ruby
  install_java
  install_kotlin
  install_dotnet
  install_rust
  install_php
  install_swift

  print_summary
}

main "$@"

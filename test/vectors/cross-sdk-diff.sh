#!/usr/bin/env bash
# Cross-SDK Differential Test for MCP
# Runs identical serialization tests across all available languages
# and reports where they disagree.
#
# Usage:
#   ./cross-sdk-diff.sh          # colored terminal output
#   ./cross-sdk-diff.sh --json   # structured JSON output
#
# Adding a language: create runners/serialize.<ext> that outputs
# JSON lines: {"test": "name", "result": "serialized_value"}

set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNERS_DIR="$DIR/runners"
JSON_MODE=0
TMPDIR="${TMPDIR:-/tmp}"
WORKDIR="$TMPDIR/mcp-diff-$$"
mkdir -p "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

if [[ "${1:-}" == "--json" ]]; then
  JSON_MODE=1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

LANGUAGES=""

# Detect and run available runners
if [ -f "$RUNNERS_DIR/serialize.js" ] && command -v node &>/dev/null; then
  node "$RUNNERS_DIR/serialize.js" > "$WORKDIR/javascript.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES javascript"
fi

if [ -f "$RUNNERS_DIR/serialize.py" ] && command -v python3 &>/dev/null; then
  python3 "$RUNNERS_DIR/serialize.py" > "$WORKDIR/python.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES python"
fi

if [ -f "$RUNNERS_DIR/serialize.rb" ] && command -v ruby &>/dev/null; then
  ruby "$RUNNERS_DIR/serialize.rb" > "$WORKDIR/ruby.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES ruby"
fi

if [ -f "$RUNNERS_DIR/serialize.php" ] && command -v php &>/dev/null; then
  php "$RUNNERS_DIR/serialize.php" > "$WORKDIR/php.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES php"
fi

if [ -f "$RUNNERS_DIR/serialize.go" ] && command -v go &>/dev/null; then
  go build -o "$WORKDIR/go-runner" "$RUNNERS_DIR/serialize.go" 2>/dev/null && \
    "$WORKDIR/go-runner" > "$WORKDIR/go.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES go"
fi

if [ -f "$RUNNERS_DIR/serialize.swift" ] && command -v swift &>/dev/null; then
  swift "$RUNNERS_DIR/serialize.swift" > "$WORKDIR/swift.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES swift"
fi

if [ -f "$RUNNERS_DIR/Serialize.java" ] && command -v javac &>/dev/null; then
  javac -d "$WORKDIR" "$RUNNERS_DIR/Serialize.java" 2>/dev/null && \
    java -cp "$WORKDIR" Serialize > "$WORKDIR/java.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES java"
fi

if [ -f "$RUNNERS_DIR/serialize.pl" ] && command -v perl &>/dev/null; then
  PERL_HASH_SEED=0 perl "$RUNNERS_DIR/serialize.pl" > "$WORKDIR/perl.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES perl"
fi

# SDK-level runners (test actual SDK serialization paths, not just stdlib)
if [ -f "$RUNNERS_DIR/serialize-sdk-python.py" ] && command -v python3 &>/dev/null; then
  python3 "$RUNNERS_DIR/serialize-sdk-python.py" > "$WORKDIR/python-sdk.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES python-sdk"
fi

if [ -f "$RUNNERS_DIR/serialize-sdk-go.go" ] && command -v go &>/dev/null; then
  go build -o "$WORKDIR/go-sdk-runner" "$RUNNERS_DIR/serialize-sdk-go.go" 2>/dev/null && \
    "$WORKDIR/go-sdk-runner" > "$WORKDIR/go-sdk.jsonl" 2>/dev/null && LANGUAGES="$LANGUAGES go-sdk"
fi

LANGUAGES=$(echo "$LANGUAGES" | xargs)
LANG_COUNT=$(echo "$LANGUAGES" | wc -w | xargs)

if [ "$LANG_COUNT" -lt 2 ]; then
  echo "ERROR: Need at least 2 languages. Found: ${LANGUAGES:-none}"
  echo "Required: node + python3. Optional: ruby, php, go"
  exit 1
fi

# Build comparison using python (available since we detected it above)
python3 - "$WORKDIR" "$LANGUAGES" "$JSON_MODE" << 'PYTHON'
import sys, os, json

workdir = sys.argv[1]
languages = sys.argv[2].split()
json_mode = sys.argv[3] == "1"

# Load all results
results = {}  # {lang: {test: result}}
for lang in languages:
    path = os.path.join(workdir, f"{lang}.jsonl")
    results[lang] = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                results[lang][entry["test"]] = entry["result"]

# Get test names from first language
test_names = list(results[languages[0]].keys())

divergences = 0
total = len(test_names)
json_output = []

if not json_mode:
    print("=== MCP Cross-SDK Differential Test ===")
    print(f"\nLanguages: {', '.join(languages)}")
    print(f"Tests: {total}\n")

for test in test_names:
    values = {}
    for lang in languages:
        values[lang] = results.get(lang, {}).get(test, "<missing>")

    unique_values = set(values.values())
    agree = len(unique_values) == 1

    if json_mode:
        json_output.append({
            "test": test,
            "agree": agree,
            "results": values
        })
    else:
        if agree:
            val = list(unique_values)[0]
            display = val if len(val) < 60 else val[:57] + "..."
            print(f"\033[0;32mAGREE\033[0m      {test}")
            print(f"             {display}\n")
        else:
            divergences += 1
            print(f"\033[0;31mDIVERGE\033[0m    {test}")
            for lang in languages:
                print(f"  \033[0;36m{lang:12}\033[0m {values[lang]}")
            print()

if json_mode:
    print(json.dumps(json_output, indent=2))
else:
    print("=== Summary ===")
    print(f"  Languages:    {len(languages)} ({', '.join(languages)})")
    print(f"  Tests:        {total}")
    print(f"  Agree:        {total - divergences}")
    print(f"  Divergences:  {divergences}")
    print()
    if divergences > 0:
        print(f"\033[0;31m{divergences} divergence(s) found across {len(languages)} languages.\033[0m")
        print("Each divergence = a case where correct implementations produce")
        print("different output for the same input.")
    else:
        print(f"\033[0;32mAll languages agree.\033[0m")

sys.exit(min(divergences, 125))
PYTHON

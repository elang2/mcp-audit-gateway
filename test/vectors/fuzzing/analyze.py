#!/usr/bin/env python3
r"""
analyze.py -- Post-process cross-SDK fuzz divergences into a categorized bug catalog.

Input
-----
/tmp/fuzz-divergences.jsonl
    One divergence per line. Each line is a JSON object with (at minimum) the
    following fields; extra fields are tolerated and ignored.

        {
          "record":       <object|array|scalar>,   # the input vector that diverged
          "minimal":      <object|array|scalar>,   # the shrunk/minimal failing input
                                                   # (falls back to `record` if absent)
          "sdkA":         "python",                # first SDK label
          "sdkB":         "csharp",                # second SDK label
          "outputA":      "<hex-sig-or-canonical>",
          "outputB":      "<hex-sig-or-canonical>",
          "majority":     "python|csharp|both|null",  # optional; if present, used
                                                   # verbatim to determine outlier
          "outlier":      "csharp",                # optional; explicit outlier
          "majorityOutput": "<hex>",               # optional; used to break ties
        }

Output
------
1. <bench-results-dir>/linux-x86-64/fuzz-bug-catalog.json
   A JSON document with the deduplicated, categorized list of bug classes.
   The bench-results directory is resolved in this order:
     - --output-dir CLI flag
     - BENCH_RESULTS_DIR environment variable
     - ./bench-results (relative to the current working directory)
2. Stdout: top 20 bug classes ranked by occurrence count.

Fingerprint
-----------
Same fingerprint = same bug class. The fingerprint is a SHA-256 hex of:

    canonical_json(minimal) + "|" + sorted(sdkA, sdkB)

so re-ordering the SDK pair does not create a new class, and structurally
identical minimal records collapse together.

Categories
----------
Inferred heuristically from the minimal record content. See CATEGORY_RULES.
A record can carry more than one tag; the tag list is deduplicated and
sorted for stable output.

Known bug cross-reference
-------------------------
The KNOWN_BUGS table encodes signatures for the 5 already-identified
cross-SDK bugs discovered in the 13-vector + nested runs on 2026-08-30:

    1. Swift NSNumber-Bool conflation           (integer 0/1 -> bool)
    2. C# System.Text.Json surrogate-pair escape (emoji -> \uD8xx\uDDxx)
    3. Jackson lone-surrogate escape             (unpaired high/low surrogate)
    4. canonicalize_value dead code             (Python-side, pre-fix vectors)
    5. PHP mbstring NFC edge                    (composed vs decomposed forms)

Any fingerprint whose (category, sdk-pair) matches a known-bug signature
is flagged status="KNOWN". Everything else is status="NEW".

Usage
-----
    python3 analyze.py                             # default paths
    python3 analyze.py --input path.jsonl          # override input
    python3 analyze.py --output-dir path/          # override output directory
    python3 analyze.py --output path.json          # override full output path
    BENCH_RESULTS_DIR=/some/path python3 analyze.py  # env-var override
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_INPUT = Path("/tmp/fuzz-divergences.jsonl")
# Output directory resolution order:
#   1. --output / --output-dir CLI flags
#   2. BENCH_RESULTS_DIR environment variable
#   3. ./bench-results (relative to the current working directory)
DEFAULT_OUTPUT_SUBPATH = Path("linux-x86-64") / "fuzz-bug-catalog.json"


def _default_output_dir() -> Path:
    env = os.environ.get("BENCH_RESULTS_DIR")
    if env:
        return Path(env)
    return Path("bench-results")


def _default_output_path() -> Path:
    return _default_output_dir() / DEFAULT_OUTPUT_SUBPATH


TOP_N = 20

# --------------------------------------------------------------------------- #
# Known-bug signatures
#
# Each entry describes ONE previously-identified bug. A fingerprint that
# matches the signature is tagged KNOWN. The match is a soft match on:
#   - required category tags (all must be present in the inferred categories)
#   - one SDK from `sdks` must appear in the (sdkA, sdkB) pair
# --------------------------------------------------------------------------- #

KNOWN_BUGS: list[dict[str, Any]] = [
    {
        "id": "swift-nsnumber-bool",
        "label": "Swift NSNumber-Bool conflation (integer 0/1 promoted to bool)",
        "sdks": {"swift"},
        "requires": {"bool-int-ambiguity"},
        "reference": "matrix-nested-5vec-10sdk.log :: vector nested-bool-int",
    },
    {
        "id": "csharp-surrogate-pair-escape",
        "label": "C# System.Text.Json escapes surrogate pairs (astral BMP)",
        "sdks": {"csharp", "dotnet"},
        "requires": {"surrogate-pair"},
        "reference": "matrix-13vec-10sdk.log :: emoji / astral vectors",
    },
    {
        "id": "jackson-lone-surrogate",
        "label": "Jackson lone-surrogate escape (unpaired \\uD8xx / \\uDCxx)",
        "sdks": {"java", "kotlin"},
        "requires": {"lone-surrogate"},
        "reference": "SDK-AUDIT.md :: Jackson string writer",
    },
    {
        "id": "python-canonicalize-value-dead-code",
        "label": "canonicalize_value dead code path (Python pre-fix)",
        "sdks": {"python"},
        "requires": {"canonicalize-value"},
        "reference": "session-2026-08-30 nested-vector-matrix findings",
    },
    {
        "id": "php-mbstring-nfc",
        "label": "PHP mbstring NFC edge (composed vs decomposed)",
        "sdks": {"php"},
        "requires": {"unicode-normalization"},
        "reference": "SDK-AUDIT.md :: PHP mbstring path",
    },
]

# --------------------------------------------------------------------------- #
# Category inference
#
# Each rule is (tag, predicate). Predicates operate on the flat string dump
# of the minimal record plus a set of "features" (booleans + counts) that
# scan_features() extracts once per record.
# --------------------------------------------------------------------------- #


def scan_features(minimal: Any) -> dict[str, Any]:
    """Extract structural + character-class features from a minimal record."""
    dump = json.dumps(minimal, ensure_ascii=False, sort_keys=True)
    ascii_dump = json.dumps(minimal, ensure_ascii=True, sort_keys=True)

    # Extract all string values (leaves) for character-level scans.
    strings: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            strings.append(v)
        elif isinstance(v, dict):
            for k, vv in v.items():
                strings.append(k)
                walk(vv)
        elif isinstance(v, list):
            for vv in v:
                walk(vv)

    walk(minimal)

    joined = "".join(strings)

    # Surrogate scans.
    has_high_surrogate = any(0xD800 <= ord(c) <= 0xDBFF for c in joined)
    has_low_surrogate = any(0xDC00 <= ord(c) <= 0xDFFF for c in joined)
    # A "paired" surrogate is a high immediately followed by a low.
    paired_surrogate = False
    lone_surrogate = False
    i = 0
    while i < len(joined):
        c = ord(joined[i])
        if 0xD800 <= c <= 0xDBFF:
            nxt = ord(joined[i + 1]) if i + 1 < len(joined) else 0
            if 0xDC00 <= nxt <= 0xDFFF:
                paired_surrogate = True
                i += 2
                continue
            lone_surrogate = True
        elif 0xDC00 <= c <= 0xDFFF:
            lone_surrogate = True
        i += 1

    # Astral / non-BMP.
    has_astral = any(ord(c) > 0xFFFF for c in joined)

    # NFC / NFD mismatch: does normalizing change the string?
    nfc_differs = any(unicodedata.normalize("NFC", s) != s for s in strings)
    nfd_differs = any(unicodedata.normalize("NFD", s) != s for s in strings)

    # Numeric boundary features.
    def flatten_scalars(v: Any) -> Iterable[Any]:
        if isinstance(v, (dict,)):
            for vv in v.values():
                yield from flatten_scalars(vv)
        elif isinstance(v, list):
            for vv in v:
                yield from flatten_scalars(vv)
        else:
            yield v

    scalars = list(flatten_scalars(minimal))
    has_bool = any(isinstance(s, bool) for s in scalars)
    # In JSON, True/False and 1/0 collide under some SDKs.
    has_int_0_or_1 = any(
        isinstance(s, int) and not isinstance(s, bool) and s in (0, 1) for s in scalars
    )
    has_float = any(isinstance(s, float) for s in scalars)
    has_negative_zero = any(
        isinstance(s, float) and s == 0.0 and str(s).startswith("-") for s in scalars
    )
    # Boundary ints: near 2**31, 2**53, 2**63.
    boundaries = (2**31, 2**31 - 1, 2**53, 2**53 - 1, 2**63, 2**63 - 1)
    has_int_boundary = any(
        isinstance(s, int) and not isinstance(s, bool) and abs(s) in boundaries
        for s in scalars
    )
    has_large_int = any(
        isinstance(s, int) and not isinstance(s, bool) and abs(s) >= 2**53
        for s in scalars
    )

    # Special float payloads (NaN/Inf typically don't round-trip through JSON,
    # but they show up as strings "NaN" / "Infinity" in some SDK dumps).
    has_special_float_string = bool(
        re.search(r'"(NaN|Infinity|-Infinity)"', ascii_dump)
    )

    # Whitespace / control chars.
    has_control_char = any(ord(c) < 0x20 and c not in "\n\r\t" for c in joined)
    has_leading_trailing_ws = any(s != s.strip() for s in strings)

    # Nesting depth.
    def depth(v: Any) -> int:
        if isinstance(v, dict):
            return 1 + max((depth(x) for x in v.values()), default=0)
        if isinstance(v, list):
            return 1 + max((depth(x) for x in v), default=0)
        return 0

    d = depth(minimal)

    return {
        "dump": dump,
        "ascii_dump": ascii_dump,
        "strings": strings,
        "has_high_surrogate": has_high_surrogate,
        "has_low_surrogate": has_low_surrogate,
        "paired_surrogate": paired_surrogate,
        "lone_surrogate": lone_surrogate,
        "has_astral": has_astral,
        "nfc_differs": nfc_differs,
        "nfd_differs": nfd_differs,
        "has_bool": has_bool,
        "has_int_0_or_1": has_int_0_or_1,
        "has_float": has_float,
        "has_negative_zero": has_negative_zero,
        "has_int_boundary": has_int_boundary,
        "has_large_int": has_large_int,
        "has_special_float_string": has_special_float_string,
        "has_control_char": has_control_char,
        "has_leading_trailing_ws": has_leading_trailing_ws,
        "depth": d,
    }


CATEGORY_RULES: list[tuple[str, Any]] = [
    ("surrogate-pair", lambda f: f["paired_surrogate"] or f["has_astral"]),
    ("lone-surrogate", lambda f: f["lone_surrogate"]),
    ("unicode-normalization", lambda f: f["nfc_differs"] or f["nfd_differs"]),
    ("bool-int-ambiguity", lambda f: f["has_bool"] and f["has_int_0_or_1"]),
    ("integer-boundary", lambda f: f["has_int_boundary"] or f["has_large_int"]),
    ("float-special", lambda f: f["has_special_float_string"] or f["has_negative_zero"]),
    ("float-precision", lambda f: f["has_float"]),
    ("control-char", lambda f: f["has_control_char"]),
    ("whitespace-trim", lambda f: f["has_leading_trailing_ws"]),
    ("deep-nesting", lambda f: f["depth"] >= 5),
    # canonicalize_value fingerprint: nested object whose value is itself a
    # single-key object -- the exact shape that hit the Python dead-code path.
    (
        "canonicalize-value",
        lambda f: bool(
            re.search(r'\{"[^"]+":\{"[^"]+":', f["dump"])
        ),
    ),
]


def categorize(minimal: Any) -> tuple[list[str], dict[str, Any]]:
    features = scan_features(minimal)
    tags = sorted({tag for tag, pred in CATEGORY_RULES if pred(features)})
    if not tags:
        tags = ["uncategorized"]
    # Don't leak the raw dumps back to the caller; they're big and noisy.
    features.pop("dump", None)
    features.pop("ascii_dump", None)
    features.pop("strings", None)
    return tags, features


# --------------------------------------------------------------------------- #
# Fingerprint + outlier
# --------------------------------------------------------------------------- #


def canonical_json(v: Any) -> str:
    """Stable, minimal-whitespace JSON for fingerprinting."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(minimal: Any, sdk_a: str, sdk_b: str) -> str:
    pair = "|".join(sorted([sdk_a or "", sdk_b or ""]))
    # Records may contain lone surrogates as adversarial input; encode with
    # surrogatepass so fingerprinting doesn't crash on them.
    payload = f"{canonical_json(minimal)}|{pair}".encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(payload).hexdigest()[:16]


def size_of(v: Any) -> int:
    return len(canonical_json(v))


def infer_outlier(rec: dict[str, Any], class_outputs: Counter) -> str | None:
    """Return which SDK is the outlier for a single divergence record.

    Priority:
      1. explicit `outlier` field in the record
      2. explicit `majority` field
      3. tie-break using the aggregate outputs seen for this bug class
    """
    if rec.get("outlier"):
        return rec["outlier"]
    majority = rec.get("majority")
    sdk_a = rec.get("sdkA")
    sdk_b = rec.get("sdkB")
    if majority in (sdk_a, sdk_b):
        return sdk_b if majority == sdk_a else sdk_a
    # Fall back to aggregate: whichever of (outputA, outputB) is rarer across
    # this bug class is the outlier.
    out_a = rec.get("outputA")
    out_b = rec.get("outputB")
    if out_a is None or out_b is None:
        return None
    ca = class_outputs.get(out_a, 0)
    cb = class_outputs.get(out_b, 0)
    if ca == cb:
        return None
    return sdk_a if ca < cb else sdk_b


# --------------------------------------------------------------------------- #
# Known-bug matching
# --------------------------------------------------------------------------- #


SDK_ALIASES: dict[str, str] = {
    "sw": "swift",
    "ts": "typescript",
    "py": "python",
    "go": "go",
    "rb": "ruby",
    "jv": "java",
    "ph": "php",
    "kt": "kotlin",
    "rs": "rust",
    "cs": "csharp",
}


def _expand_label(label: str) -> set[str]:
    lo = (label or "").lower()
    out = {lo}
    if lo in SDK_ALIASES:
        out.add(SDK_ALIASES[lo])
    return out


def match_known(tags: set[str], sdk_a: str, sdk_b: str) -> dict[str, Any] | None:
    pair = _expand_label(sdk_a) | _expand_label(sdk_b)
    for bug in KNOWN_BUGS:
        if not bug["requires"].issubset(tags):
            continue
        if not bug["sdks"] & pair:
            continue
        return {"id": bug["id"], "label": bug["label"], "reference": bug["reference"]}
    return None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError as e:
                print(
                    f"warning: {path}:{lineno} skipped (invalid JSON: {e})",
                    file=sys.stderr,
                )
    return records


def build_catalog(records: list[dict[str, Any]]) -> dict[str, Any]:
    # Pass 1: group by fingerprint, count outputs per class for outlier tiebreak.
    groups: dict[str, dict[str, Any]] = {}
    class_outputs: dict[str, Counter] = defaultdict(Counter)

    for rec in records:
        minimal = rec.get("minimal", rec.get("record"))
        sdk_a = rec.get("sdkA") or ""
        sdk_b = rec.get("sdkB") or ""
        fp = fingerprint(minimal, sdk_a, sdk_b)
        if fp not in groups:
            groups[fp] = {
                "records": [],
                "smallest": minimal,
                "smallest_size": size_of(minimal),
                "sdk_pair": tuple(sorted([sdk_a, sdk_b])),
            }
        g = groups[fp]
        g["records"].append(rec)
        sz = size_of(minimal)
        if sz < g["smallest_size"]:
            g["smallest"] = minimal
            g["smallest_size"] = sz
        for out in (rec.get("outputA"), rec.get("outputB")):
            if out is not None:
                class_outputs[fp][out] += 1

    # Pass 2: build catalog entries.
    catalog: list[dict[str, Any]] = []
    for fp, g in groups.items():
        smallest = g["smallest"]
        tags, _features = categorize(smallest)
        sdk_a, sdk_b = g["sdk_pair"]
        # Outlier: per-record votes, most common wins.
        outlier_votes: Counter = Counter()
        for rec in g["records"]:
            o = infer_outlier(rec, class_outputs[fp])
            if o:
                outlier_votes[o] += 1
        outlier = outlier_votes.most_common(1)[0][0] if outlier_votes else None
        known = match_known(set(tags), sdk_a, sdk_b)

        catalog.append(
            {
                "fingerprint": fp,
                "count": len(g["records"]),
                "sdk_pair": [sdk_a, sdk_b],
                "outlier": outlier,
                "minimal_record": smallest,
                "minimal_size_bytes": g["smallest_size"],
                "categories": tags,
                "status": "KNOWN" if known else "NEW",
                "known_bug": known,
            }
        )

    catalog.sort(key=lambda e: (-e["count"], e["fingerprint"]))
    total_divergences = sum(e["count"] for e in catalog)
    new_classes = sum(1 for e in catalog if e["status"] == "NEW")
    known_classes = sum(1 for e in catalog if e["status"] == "KNOWN")

    return {
        "schema_version": 1,
        "generated_by": "test/vectors/fuzzing/analyze.py",
        "input_records": len(records),
        "unique_bug_classes": len(catalog),
        "total_divergences": total_divergences,
        "known_bug_classes": known_classes,
        "new_bug_classes": new_classes,
        "known_bug_reference_table": [
            {
                "id": b["id"],
                "label": b["label"],
                "sdks": sorted(b["sdks"]),
                "requires": sorted(b["requires"]),
                "reference": b["reference"],
            }
            for b in KNOWN_BUGS
        ],
        "bug_classes": catalog,
    }


def print_top(catalog: dict[str, Any], n: int = TOP_N) -> None:
    entries = catalog["bug_classes"][:n]
    print(
        f"\nfuzz-bug-catalog: {catalog['unique_bug_classes']} unique classes "
        f"from {catalog['input_records']} divergences "
        f"({catalog['known_bug_classes']} KNOWN, {catalog['new_bug_classes']} NEW)\n"
    )
    header = f"{'rank':>4}  {'count':>6}  {'status':<6}  {'fingerprint':<16}  {'pair':<24}  {'outlier':<10}  categories"
    print(header)
    print("-" * len(header))
    for i, e in enumerate(entries, 1):
        pair = "/".join(e["sdk_pair"]) if e["sdk_pair"] else "?"
        outlier = e["outlier"] or "-"
        cats = ",".join(e["categories"])
        marker = e["status"]
        print(
            f"{i:>4}  {e['count']:>6}  {marker:<6}  {e['fingerprint']:<16}  "
            f"{pair:<24}  {outlier:<10}  {cats}"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Full path to output JSON file (overrides --output-dir).",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Directory to write the catalog under (as "
            "<dir>/linux-x86-64/fuzz-bug-catalog.json). Defaults to "
            "$BENCH_RESULTS_DIR or ./bench-results."
        ),
    )
    ap.add_argument("--top", type=int, default=TOP_N)
    args = ap.parse_args(argv)

    if args.output is not None:
        output_path = args.output
    elif args.output_dir is not None:
        output_path = args.output_dir / DEFAULT_OUTPUT_SUBPATH
    else:
        output_path = _default_output_path()

    if not args.input.exists():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 2

    records = load_jsonl(args.input)
    if not records:
        print(f"error: no divergences parsed from {args.input}", file=sys.stderr)
        return 2

    catalog = build_catalog(records)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # ensure_ascii=True so lone surrogates in adversarial input don't blow
    # up the file writer (utf-8 rejects lone surrogates).
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=True)
        f.write("\n")

    print(f"wrote {output_path}", file=sys.stderr)
    print_top(catalog, n=args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

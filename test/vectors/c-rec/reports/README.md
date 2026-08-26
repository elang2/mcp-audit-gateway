# C-REC reports (generated payload directory)

Hosts a generated markdown file that mirrors the raw C-REC data (KAT
verification, 11-row side-by-side table, five producer-requirement
vectors) shown on the SEP-3004 PR discussion at
[modelcontextprotocol/modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004).

The comment carries the interpretive prose; this file carries the
byte-level data.

## Files

- `build-comment-payload.ts` — the generator. Imports canonicalizers and
  fixture inputs from `../harness.ts` (single source of truth) and
  prints the data as markdown. Runs via tsx.
- `SEP-3004-comment-payload.md` — committed generated output. Exists so
  a reader arriving at the repo without a Node install can still see
  the exact bytes and hashes the PR comment references.

## Regenerate

```bash
npm run c-rec:report
```

Runs `build-comment-payload.ts --write` and overwrites the committed
`SEP-3004-comment-payload.md` in place.

## Drift gate

CI regenerates the payload on every push and diffs against the
committed file. If a fixture, canonicalizer, or generator change
produces different bytes without a refresh, the build fails.

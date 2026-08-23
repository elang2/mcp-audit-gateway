---
name: SDK Serialization Divergence
about: Report a cross-SDK serialization divergence found by differential testing
title: "[divergence] SDK_NAME: TEST_NAME produces different output"
labels: cross-sdk, divergence
---

## Divergence

**SDK:** <!-- e.g., TypeScript, Python, Go -->
**Test:** <!-- e.g., float_1e20, negative_zero -->
**Version:** <!-- SDK version tested -->

## Expected (reference: JavaScript/Node.js)

```
<!-- paste expected output -->
```

## Actual

```
<!-- paste actual output from the divergent SDK -->
```

## Reproduction

```sh
# Clone and run:
git clone https://github.com/elang2/mcp-audit-gateway.git
cd mcp-audit-gateway/test/vectors
./cross-sdk-diff.sh --json | python3 -c "
import sys, json
for t in json.loads(sys.stdin.read()):
    if t['test'] == 'TEST_NAME' and not t['agree']:
        for lang, val in t['results'].items():
            print(f'{lang}: {val}')
"
```

## Impact

<!-- How does this divergence affect real-world MCP usage? -->
<!-- e.g., "Content digests computed in Python won't match those from TypeScript for tool definitions containing this value" -->

## Spec reference

<!-- Which part of the MCP spec or JSON-RPC spec is ambiguous here? -->

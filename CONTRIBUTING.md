# Contributing

Contributions welcome. Here's how to get going.

## Setup

```bash
git clone <repo-url> && cd mcp-audit-gateway
npm install
npm run build
npm test
```

Requires Node.js 20+.

## Running tests

```bash
npm test              # all tests
npx vitest run src/attestation/  # just attestation tests
```

Tests use Vitest and run against real filesystem paths (no mocks for the audit log). Temp files go in `/tmp` and are cleaned up in `afterEach`.

## Code style

TypeScript strict mode. No `any` unless interfacing with the MCP SDK's dynamic types. Keep functions short and avoid class inheritance.

## Pull requests

One feature or fix per PR. Include a test that fails without the fix and passes with it.

If you're changing the attestation or signing logic, run the full verification test suite and include `verify` CLI output in the PR description showing the audit log validates end-to-end.

## Architecture decisions

The gateway is a transparent proxy. It should never modify tool call arguments or results. Its job is to observe, sign, and enforce policy. If a feature requires mutating upstream data, it belongs in a different layer.

## Security

If you find a vulnerability in the signing, chain verification, or policy enforcement, please report it privately before opening a public issue.

#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Gateway, ToolCallError } from "./proxy/gateway.js";
import { GatewayConfigSchema } from "./types.js";

const USAGE = `mcp-audit — cryptographic proof of what your AI agents did

Commands:
  wrap -- <cmd>     Wrap any MCP server with transparent audit logging
  tail              Live stream of audit records
  verify <log>      Verify integrity of an audit log file
  serve [config]    Start the full gateway (multi-upstream, policy, OTel)
  keygen [dir]      Generate Ed25519 key pair
  help              Show this help

Examples:
  mcp-audit wrap -- npx @modelcontextprotocol/server-github
  mcp-audit tail
  mcp-audit verify ~/.mcp-audit/audit.jsonl
  mcp-audit serve ./gateway.config.json
`;

async function main() {
  const [command = "serve", ...args] = process.argv.slice(2);

  switch (command) {
    case "wrap":
      return wrap(args);
    case "tail":
      return tail();
    case "serve":
      return serve(args[0]);
    case "verify":
      return verify(args[0]);
    case "keygen":
      return keygen(args[0]);
    case "help":
    case "--help":
    case "-h":
      console.log(USAGE);
      return;
    default:
      if (command.endsWith(".json")) {
        return serve(command);
      }
      console.error(`Unknown command: ${command}`);
      console.log(USAGE);
      process.exit(1);
  }
}

async function wrap(args: string[]) {
  const dashDash = args.indexOf("--");
  const cmdArgs = dashDash >= 0 ? args.slice(dashDash + 1) : args;

  if (cmdArgs.length === 0) {
    console.error("Usage: mcp-audit wrap -- <command> [args...]");
    console.error("Example: mcp-audit wrap -- npx @modelcontextprotocol/server-github");
    process.exit(1);
  }

  const [command, ...rest] = cmdArgs;
  const { runWrapProxy } = await import("./wrap/proxy.js");
  await runWrapProxy(command, rest);
}

async function tail() {
  const { homedir } = await import("node:os");
  const { join } = await import("node:path");
  const { createReadStream, watch } = await import("node:fs");
  const { stat } = await import("node:fs/promises");

  const logPath = join(homedir(), ".mcp-audit", "audit.jsonl");

  try {
    await stat(logPath);
  } catch {
    console.error(`No audit log found at ${logPath}`);
    console.error("Start wrapping an MCP server first: mcp-audit wrap -- <command>");
    process.exit(1);
  }

  console.log(`Tailing ${logPath}...\n`);

  let position = 0;
  const s = await stat(logPath);
  position = s.size;

  const printLine = (line: string) => {
    try {
      const entry = JSON.parse(line);
      const status = entry.success ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
      const dur = `${entry.durationMs}ms`.padStart(7);
      const tool = (entry.toolName ?? "unknown").padEnd(30);
      const time = entry.timestamp?.substring(11, 19) ?? "";
      console.log(`${status} ${time} ${tool} ${dur}  ${entry.id.substring(0, 8)}`);
    } catch {}
  };

  const readNewLines = () => {
    const stream = createReadStream(logPath, { start: position, encoding: "utf-8" });
    let buffer = "";
    stream.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line.trim()) printLine(line);
      }
      position += Buffer.byteLength(chunk as string);
    });
  };

  readNewLines();
  watch(logPath, () => readNewLines());
}

async function serve(configPath?: string) {
  const resolved = resolve(configPath ?? "gateway.config.json");

  let rawConfig: unknown;
  try {
    const content = await readFile(resolved, "utf-8");
    rawConfig = JSON.parse(content);
  } catch (err) {
    console.error(`Failed to read config from ${resolved}:`, err);
    process.exit(1);
  }

  const parsed = GatewayConfigSchema.safeParse(rawConfig);
  if (!parsed.success) {
    console.error("Invalid configuration:");
    for (const issue of parsed.error.issues) {
      console.error(`  ${issue.path.join(".")}: ${issue.message}`);
    }
    process.exit(1);
  }

  const config = parsed.data;
  const gateway = new Gateway(config);
  await gateway.init();

  console.log(`${config.name} v${config.version} started`);
  console.log(`  Transport: ${config.listen.transport}`);
  console.log(`  Upstreams: ${config.upstreams.length}`);
  console.log(`  Attestation: ${config.attestation.enabled ? config.attestation.algorithm : "disabled"}`);
  console.log(`  Telemetry: ${config.telemetry.enabled ? "enabled" : "disabled"}`);
  console.log(`  Audit log: ${config.auditLog.enabled ? config.auditLog.path : "disabled"}`);
  console.log(`  Policy: default=${config.policy.defaultEffect}, ${config.policy.rules.length} rules`);
  console.log();

  if (config.listen.transport === "streamable-http") {
    const { createServer } = await import("node:http");
    const server = createServer(async (req, res) => {
      if (req.url === "/health") {
        const status = gateway.getStatus();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(status));
        return;
      }

      if (req.url === "/discover") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(gateway.getServerDiscover()));
        return;
      }

      if (req.method === "POST" && req.url === "/mcp") {
        const MAX_BODY_SIZE = 10 * 1024 * 1024;
        let body = "";
        let size = 0;
        let aborted = false;
        const principalHeader = config.listen.principalHeader;
        const transportPrincipal = principalHeader
          ? (req.headers[principalHeader.toLowerCase()] as string | undefined)
          : undefined;
        req.on("data", (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY_SIZE) {
            aborted = true;
            res.writeHead(413, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              id: null,
              error: { code: -32600, message: "Request body too large" },
            }));
            req.destroy();
            return;
          }
          body += chunk;
        });
        req.on("end", async () => {
          if (aborted) return;
          let requestId: unknown = null;
          try {
            const request = JSON.parse(body);
            requestId = request.id ?? null;
            const result = await handleJsonRpc(gateway, request, transportPrincipal);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              id: requestId,
              error: { code: -32603, message: String(err) },
            }));
          }
        });
        return;
      }

      res.writeHead(404);
      res.end("Not found");
    });

    server.listen(config.listen.port, config.listen.host, () => {
      console.log(`Listening on http://${config.listen.host}:${config.listen.port}`);
    });

    process.on("SIGINT", async () => {
      await gateway.shutdown();
      server.close();
      process.exit(0);
    });
  } else {
    console.log("stdio transport: reading JSON-RPC from stdin");
    const { createInterface } = await import("node:readline");
    const rl = createInterface({ input: process.stdin });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let requestId: unknown = null;
      try {
        const request = JSON.parse(line);
        requestId = request.id ?? null;
        const result = await handleJsonRpc(gateway, request);
        process.stdout.write(JSON.stringify(result) + "\n");
      } catch (err) {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: requestId,
            error: { code: -32603, message: String(err) },
          }) + "\n",
        );
      }
    }
  }
}

async function verify(logPath?: string) {
  if (!logPath) {
    console.error("Usage: mcp-audit-gateway verify <audit-log-path>");
    process.exit(1);
  }

  const resolved = resolve(logPath);
  const { verifyAuditLog } = await import("./attestation/verify.js");
  const { HmacSigner, Ed25519Signer } = await import("./attestation/signer.js");

  const { homedir } = await import("node:os");
  const { join } = await import("node:path");

  const configPath = process.env.GATEWAY_CONFIG ?? "gateway.config.json";
  let signer: import("./attestation/signer.js").Signer;

  try {
    const content = await readFile(resolve(configPath), "utf-8");
    const config = GatewayConfigSchema.parse(JSON.parse(content));

    if (config.attestation.algorithm === "hmac-sha256" && config.attestation.secret) {
      signer = new HmacSigner(config.attestation.secret);
    } else {
      const edSigner = new Ed25519Signer(config.attestation.keyPath);
      await edSigner.init();
      signer = edSigner;
    }
  } catch {
    const wrapKeyPath = join(homedir(), ".mcp-audit", "key.hex");
    try {
      const keyHex = await readFile(wrapKeyPath, "utf-8");
      signer = new HmacSigner(keyHex.trim());
    } catch {
      console.error("Cannot find signing key. Checked gateway.config.json and ~/.mcp-audit/key.hex");
      process.exit(1);
    }
  }

  console.log(`Verifying ${resolved}...`);
  const result = await verifyAuditLog(resolved, signer, { verifyChain: true });

  console.log(`\nResults:`);
  console.log(`  Total records: ${result.total}`);
  console.log(`  Valid: ${result.valid}`);
  console.log(`  Invalid: ${result.invalid}`);

  if (result.errors.length > 0) {
    console.log(`\nErrors:`);
    for (const err of result.errors.slice(0, 20)) {
      console.log(`  Line ${err.line} [${err.id}]: ${err.reason}`);
    }
    if (result.errors.length > 20) {
      console.log(`  ... and ${result.errors.length - 20} more`);
    }
    process.exit(1);
  }

  console.log("\nAll records verified successfully.");
}

async function keygen(dir?: string) {
  const outputDir = resolve(dir ?? ".");
  const { generateKeyPair } = await import("./attestation/keygen.js");

  const { publicKeyPath, privateKeyPath } = await generateKeyPair(outputDir);
  console.log(`Key pair generated:`);
  console.log(`  Private key: ${privateKeyPath}`);
  console.log(`  Public key:  ${publicKeyPath}`);
  console.log(`\nAdd to gateway.config.json:`);
  console.log(`  "attestation": { "enabled": true, "algorithm": "ed25519", "keyPath": "${privateKeyPath}" }`);
}

async function handleJsonRpc(
  gateway: Gateway,
  request: { id?: unknown; method?: string; params?: Record<string, unknown> },
  transportPrincipal?: string,
) {
  const { id, method, params } = request;
  const principal = transportPrincipal ?? undefined;
  const traceContext = (params?._meta as Record<string, unknown>)?.traceContext as
    | { traceparent?: string; tracestate?: string }
    | undefined;

  switch (method) {
    case "server/discover":
      return { jsonrpc: "2.0", id, result: gateway.getServerDiscover() };

    case "tools/list": {
      const listResult = await gateway.handleToolsList(principal);
      return { jsonrpc: "2.0", id, result: listResult };
    }

    case "tools/call": {
      const toolName = params?.name as string;
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      try {
        const { result, auditRecord } = await gateway.handleToolsCall(
          toolName,
          args,
          principal,
          traceContext,
        );
        return {
          jsonrpc: "2.0",
          id,
          result: {
            ...(result as object),
            _meta: {
              "x-gateway-attestation/v1": {
                auditId: auditRecord.id,
                attestation: auditRecord.attestation,
                timestamp: auditRecord.timestamp,
              },
            },
          },
        };
      } catch (err) {
        if (err instanceof ToolCallError) {
          return {
            jsonrpc: "2.0",
            id,
            error: {
              code: err.code,
              message: err.message,
              data: {
                _meta: {
                  "x-gateway-attestation/v1": {
                    auditId: err.auditRecord.id,
                    attestation: err.auditRecord.attestation,
                    timestamp: err.auditRecord.timestamp,
                  },
                },
              },
            },
          };
        }
        throw err;
      }
    }

    case "x-gateway-routing/v1/status":
      return { jsonrpc: "2.0", id, result: gateway.getStatus() };

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});

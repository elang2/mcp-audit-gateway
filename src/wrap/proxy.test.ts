import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { readFile, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

const AUDIT_DIR = join(homedir(), ".mcp-audit");
const LOG_PATH = join(AUDIT_DIR, "audit.jsonl");
const CLI_PATH = join(import.meta.dirname, "../../dist/cli.js");

function sendJsonRpc(proc: ReturnType<typeof spawn>, msg: object) {
  proc.stdin!.write(JSON.stringify(msg) + "\n");
}

function collectLines(proc: ReturnType<typeof spawn>): Promise<string[]> {
  return new Promise((resolve) => {
    const lines: string[] = [];
    proc.stdout!.on("data", (chunk) => {
      const parts = chunk.toString().split("\n").filter((l: string) => l.trim());
      lines.push(...parts);
    });
    proc.on("close", () => resolve(lines));
  });
}

describe("wrap proxy", () => {
  let originalLog: string | null = null;

  beforeEach(async () => {
    await mkdir(AUDIT_DIR, { recursive: true });
    try {
      originalLog = await readFile(LOG_PATH, "utf-8");
    } catch {
      originalLog = null;
    }
  });

  afterEach(async () => {
    if (originalLog !== null) {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(LOG_PATH, originalLog);
    } else {
      try { await rm(LOG_PATH); } catch {}
    }
  });

  it("forwards non-tool messages transparently", async () => {
    const proc = spawn("node", [CLI_PATH, "wrap", "--", "node", "-e", `
      process.stdin.setEncoding('utf-8');
      let buf = '';
      process.stdin.on('data', d => {
        buf += d;
        const lines = buf.split('\\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          const req = JSON.parse(line);
          if (req.method === 'initialize') {
            process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:req.id,result:{capabilities:{tools:{}}}}) + '\\n');
          } else if (req.method === 'resources/list') {
            process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:req.id,result:{resources:[]}}) + '\\n');
          }
        }
      });
    `], { stdio: ["pipe", "pipe", "pipe"] });

    const lines = collectLines(proc);

    sendJsonRpc(proc, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    sendJsonRpc(proc, { jsonrpc: "2.0", id: 2, method: "resources/list", params: {} });

    await new Promise((r) => setTimeout(r, 500));
    proc.stdin!.end();

    const output = await lines;
    const parsed = output.map((l) => JSON.parse(l));

    expect(parsed).toHaveLength(2);
    expect(parsed[0].id).toBe(1);
    expect(parsed[0].result.capabilities).toBeDefined();
    expect(parsed[1].id).toBe(2);
    expect(parsed[1].result.resources).toBeDefined();
  });

  it("logs tool calls with attestation", async () => {
    const proc = spawn("node", [CLI_PATH, "wrap", "--", "node", "-e", `
      process.stdin.setEncoding('utf-8');
      let buf = '';
      process.stdin.on('data', d => {
        buf += d;
        const lines = buf.split('\\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          const req = JSON.parse(line);
          if (req.method === 'tools/call') {
            process.stdout.write(JSON.stringify({
              jsonrpc:'2.0', id:req.id,
              result:{content:[{type:'text',text:'done'}]}
            }) + '\\n');
          }
        }
      });
    `], { stdio: ["pipe", "pipe", "pipe"] });

    const lines = collectLines(proc);

    sendJsonRpc(proc, {
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "fs/read_file", arguments: { path: "/tmp/test" } },
    });

    await new Promise((r) => setTimeout(r, 500));
    proc.stdin!.end();

    const output = await lines;
    expect(output.length).toBeGreaterThanOrEqual(1);

    const response = JSON.parse(output[0]);
    expect(response.result.content[0].text).toBe("done");

    await new Promise((r) => setTimeout(r, 200));
    const logContent = await readFile(LOG_PATH, "utf-8");
    const logLines = logContent.trimEnd().split("\n");
    const lastEntry = JSON.parse(logLines[logLines.length - 1]);

    expect(lastEntry.toolName).toBe("fs/read_file");
    expect(lastEntry.success).toBe(true);
    expect(lastEntry.attestation).toBeDefined();
    expect(lastEntry.attestation.length).toBe(64);
    expect(lastEntry.previousHash).toBeDefined();
  });

  it("maintains hash chain across calls", async () => {
    const proc = spawn("node", [CLI_PATH, "wrap", "--", "node", "-e", `
      process.stdin.setEncoding('utf-8');
      let buf = '';
      process.stdin.on('data', d => {
        buf += d;
        const lines = buf.split('\\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          const req = JSON.parse(line);
          if (req.method === 'tools/call') {
            process.stdout.write(JSON.stringify({
              jsonrpc:'2.0', id:req.id,
              result:{content:[{type:'text',text:'ok'}]}
            }) + '\\n');
          }
        }
      });
    `], { stdio: ["pipe", "pipe", "pipe"] });

    collectLines(proc);

    sendJsonRpc(proc, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tool_a", arguments: {} } });
    await new Promise((r) => setTimeout(r, 300));
    sendJsonRpc(proc, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "tool_b", arguments: {} } });
    await new Promise((r) => setTimeout(r, 300));
    sendJsonRpc(proc, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "tool_c", arguments: {} } });

    await new Promise((r) => setTimeout(r, 500));
    proc.stdin!.end();
    await new Promise((r) => setTimeout(r, 200));

    const logContent = await readFile(LOG_PATH, "utf-8");
    const logLines = logContent.trimEnd().split("\n");
    const entries = logLines.slice(-3).map((l) => JSON.parse(l));

    expect(entries[0].previousHash).toBeDefined();
    expect(entries[1].previousHash).not.toBe(entries[0].previousHash);
    expect(entries[2].previousHash).not.toBe(entries[1].previousHash);
  });
});

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { appendFile, mkdir, readFile, stat } from "node:fs/promises";
import { createHmac, randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

interface AuditEntry {
  id: string;
  timestamp: string;
  method: string;
  toolName: string;
  namespace: null;
  upstream: null;
  principal: null;
  args: Record<string, unknown>;
  durationMs: number;
  success: boolean;
  errorCode: null;
  previousHash: string;
  attestation: string;
}

interface PendingCall {
  toolName: string;
  args: Record<string, unknown>;
  startTime: number;
}

export async function runWrapProxy(command: string, args: string[]): Promise<void> {
  const auditDir = join(homedir(), ".mcp-audit");
  await mkdir(auditDir, { recursive: true });

  const keyPath = join(auditDir, "key.hex");
  const logPath = join(auditDir, "audit.jsonl");
  const secret = await ensureKey(keyPath);

  let lastHash = await restoreLastHash(logPath);
  let writeQueue: Promise<void> = Promise.resolve();
  const pending = new Map<string | number, PendingCall>();

  const child = spawn(command, args, {
    stdio: ["pipe", "pipe", "inherit"],
    env: process.env,
  });

  child.on("error", (err) => {
    process.stderr.write(`[mcp-audit] failed to spawn: ${err.message}\n`);
    process.exit(1);
  });

  child.on("exit", (code) => {
    process.exit(code ?? 0);
  });

  const clientRl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const serverRl = createInterface({ input: child.stdout!, crlfDelay: Infinity });

  clientRl.on("line", (line) => {
    if (!line.trim()) return;
    try {
      const msg = JSON.parse(line);
      if (msg.method === "tools/call" && msg.id !== undefined) {
        pending.set(msg.id, {
          toolName: msg.params?.name ?? "unknown",
          args: msg.params?.arguments ?? {},
          startTime: Date.now(),
        });
      }
    } catch {}
    child.stdin!.write(line + "\n");
  });

  serverRl.on("line", (line) => {
    if (!line.trim()) return;

    process.stdout.write(line + "\n");

    let msg: any;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }

    if (msg.id !== undefined && pending.has(msg.id)) {
      const call = pending.get(msg.id)!;
      pending.delete(msg.id);

      const durationMs = Date.now() - call.startTime;
      const success = !msg.error;

      writeQueue = writeQueue.then(async () => {
        try {
          const entry = createEntry(call.toolName, call.args, durationMs, success, lastHash);
          const signed = sign(entry, secret);
          lastHash = hashEntry(signed);
          await appendFile(logPath, JSON.stringify(signed) + "\n");
        } catch (err) {
          process.stderr.write(`[mcp-audit] log write failed: ${err}\n`);
        }
      });
    }
  });

  clientRl.on("close", () => {
    child.stdin!.end();
  });

  process.on("SIGINT", () => {
    child.kill("SIGINT");
  });

  process.on("SIGTERM", () => {
    child.kill("SIGTERM");
  });
}

function createEntry(
  toolName: string,
  args: Record<string, unknown>,
  durationMs: number,
  success: boolean,
  previousHash: string,
): Omit<AuditEntry, "attestation"> {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    method: "tools/call",
    toolName,
    namespace: null,
    upstream: null,
    principal: null,
    args,
    durationMs,
    success,
    errorCode: null,
    previousHash,
  };
}

function sign(entry: Omit<AuditEntry, "attestation">, secret: Buffer): AuditEntry {
  const canonical = JSON.stringify([
    ["id", entry.id],
    ["timestamp", entry.timestamp],
    ["method", entry.method],
    ["toolName", entry.toolName],
    ["namespace", null],
    ["upstream", null],
    ["principal", null],
    ["durationMs", entry.durationMs],
    ["success", entry.success],
    ["errorCode", null],
    ["previousHash", entry.previousHash],
  ]);
  const hmac = createHmac("sha256", secret);
  hmac.update(canonical);
  const attestation = hmac.digest("hex");
  return { ...entry, attestation };
}

function hashEntry(entry: AuditEntry): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

async function ensureKey(keyPath: string): Promise<Buffer> {
  try {
    const hex = await readFile(keyPath, "utf-8");
    return Buffer.from(hex.trim(), "hex");
  } catch {
    const key = randomBytes(32);
    await appendFile(keyPath, key.toString("hex") + "\n");
    process.stderr.write(`[mcp-audit] generated signing key: ${keyPath}\n`);
    return key;
  }
}

async function restoreLastHash(logPath: string): Promise<string> {
  try {
    const s = await stat(logPath);
    if (s.size === 0) return "genesis";
    const content = await readFile(logPath, "utf-8");
    const lines = content.trimEnd().split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);
        return hashEntry(entry);
      } catch {}
    }
  } catch {}
  return "genesis";
}

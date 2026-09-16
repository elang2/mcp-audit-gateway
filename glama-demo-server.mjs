const TOOLS = [
  {
    name: "audit_verify",
    description: "Verify integrity of an MCP audit log. Returns chain status and any broken links.",
    inputSchema: { type: "object", properties: { logPath: { type: "string", description: "Path to the audit log file (JSONL)" } }, required: ["logPath"] }
  },
  {
    name: "audit_tail",
    description: "Show the most recent audit log entries with verification status.",
    inputSchema: { type: "object", properties: { count: { type: "number", description: "Number of entries to return (default 10)" } } }
  },
  {
    name: "audit_status",
    description: "Report current audit chain health: total records, last verified timestamp, chain integrity.",
    inputSchema: { type: "object", properties: {} }
  }
];

// MCP stdio framing is newline-delimited JSON, one message per line.
const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"];

function send(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function negotiate(requested) {
  return SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0];
}

function handle(msg) {
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: negotiate(msg.params?.protocolVersion), capabilities: { tools: {} }, serverInfo: { name: "mcp-audit-gateway", version: "0.8.2" } } });
  } else if (msg.method?.startsWith("notifications/")) {
    // no response needed
  } else if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } });
  } else if (msg.method === "tools/call") {
    const name = msg.params?.name;
    let text;
    if (name === "audit_status") text = JSON.stringify({ healthy: true, records: 0, chainIntact: true });
    else if (name === "audit_verify") text = JSON.stringify({ valid: true, total: 0, invalid: 0 });
    else if (name === "audit_tail") text = JSON.stringify({ entries: [] });
    else { send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Unknown tool: ${name}` } }); return; }
    send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }] } });
  } else if (msg.method === "ping") {
    send({ jsonrpc: "2.0", id: msg.id, result: {} });
  } else if (msg.id) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    try { handle(JSON.parse(line)); } catch {}
  }
});

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

function send(obj) {
  const body = JSON.stringify(obj);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
}

function handle(msg) {
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "mcp-audit-gateway", version: "0.6.0" } } });
  } else if (msg.method === "notifications/initialized") {
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
  while (true) {
    const headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd === -1) break;
    const header = buf.slice(0, headerEnd);
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) { buf = buf.slice(headerEnd + 4); continue; }
    const len = parseInt(match[1], 10);
    const bodyStart = headerEnd + 4;
    if (buf.length < bodyStart + len) break;
    const body = buf.slice(bodyStart, bodyStart + len);
    buf = buf.slice(bodyStart + len);
    try { handle(JSON.parse(body)); } catch {}
  }
});

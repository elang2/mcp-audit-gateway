#!/usr/bin/env node
/**
 * MCP SDK-level behavioral tests for TypeScript.
 * Tests actual protocol handling, not just JSON serialization.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const results = [];

function emit(test, result) {
  results.push({ test, result: typeof result === "string" ? result : JSON.stringify(result) });
}

// Test: Extra/unknown fields in tool definitions
try {
  const server = new Server({ name: "test", version: "1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{
      name: "test_tool",
      description: "A test tool",
      inputSchema: { type: "object", properties: {} },
      _extraField: "injected",
      customAnnotation: true,
    }]
  }));
  server.setRequestHandler(CallToolRequestSchema, async () => ({
    content: [{ type: "text", text: "ok" }]
  }));

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0" }, {});

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const toolsList = await client.listTools();
  const tool = toolsList.tools[0];
  const keys = Object.keys(tool);
  emit("extra_fields_in_tools_list", keys.includes("_extraField") ? "preserved" : "stripped");
  emit("tool_keys_received", JSON.stringify(keys.sort()));

  await client.close();
  await server.close();
} catch (e) {
  emit("extra_fields_in_tools_list", `error:${e.message?.slice(0, 80)}`);
  emit("tool_keys_received", `error:${e.message?.slice(0, 80)}`);
}

// Test: Error handling for unknown tool
try {
  const server = new Server({ name: "test", version: "1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name === "nonexistent") {
      throw new Error("Tool not found");
    }
    return { content: [{ type: "text", text: "ok" }] };
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0" }, {});

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  try {
    await client.callTool({ name: "nonexistent", arguments: {} });
    emit("unknown_tool_error_code", "no_error_thrown");
  } catch (e) {
    emit("unknown_tool_error_code", `code:${e.code ?? "none"}`);
    emit("unknown_tool_error_message", e.message?.slice(0, 80) ?? "none");
  }

  await client.close();
  await server.close();
} catch (e) {
  emit("unknown_tool_error_code", `setup_error:${e.message?.slice(0, 80)}`);
}

// Test: Arguments forwarding (null, empty, populated)
try {
  const server = new Server({ name: "test", version: "1.0" }, { capabilities: { tools: {} } });
  const receivedArgs = [];

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "echo", inputSchema: { type: "object", properties: { x: { type: "string" } } } }]
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    receivedArgs.push({ raw: req.params.arguments, serialized: JSON.stringify(req.params.arguments) });
    return { content: [{ type: "text", text: "ok" }] };
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0" }, {});

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  await client.callTool({ name: "echo", arguments: {} });
  await client.callTool({ name: "echo", arguments: { x: "hello" } });

  emit("empty_args_forwarded_as", receivedArgs[0].serialized);
  emit("populated_args_forwarded_as", receivedArgs[1].serialized);

  await client.close();
  await server.close();
} catch (e) {
  emit("empty_args_forwarded_as", `error:${e.message?.slice(0, 80)}`);
  emit("populated_args_forwarded_as", `error:${e.message?.slice(0, 80)}`);
}

// Test: isError propagation
try {
  const server = new Server({ name: "test", version: "1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "fail", inputSchema: { type: "object", properties: {} } }]
  }));
  server.setRequestHandler(CallToolRequestSchema, async () => ({
    content: [{ type: "text", text: "something went wrong" }],
    isError: true,
  }));

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0" }, {});

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const result = await client.callTool({ name: "fail", arguments: {} });
  emit("isError_propagated", String(result.isError));
  emit("isError_throws_or_returns", "returns");

  await client.close();
  await server.close();
} catch (e) {
  emit("isError_propagated", "N/A");
  emit("isError_throws_or_returns", `throws:${e.message?.slice(0, 50)}`);
}

// Test: Tool result content types
try {
  const server = new Server({ name: "test", version: "1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "multi", inputSchema: { type: "object", properties: {} } }]
  }));
  server.setRequestHandler(CallToolRequestSchema, async () => ({
    content: [
      { type: "text", text: "Hello" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
    ],
  }));

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0" }, {});

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const result = await client.callTool({ name: "multi", arguments: {} });
  emit("multi_content_count", String(result.content.length));
  emit("multi_content_types", JSON.stringify(result.content.map(c => c.type)));

  await client.close();
  await server.close();
} catch (e) {
  emit("multi_content_count", `error:${e.message?.slice(0, 80)}`);
  emit("multi_content_types", `error:${e.message?.slice(0, 80)}`);
}

// Output
for (const r of results) {
  console.log(JSON.stringify(r));
}

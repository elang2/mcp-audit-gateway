#!/usr/bin/env node
// Serialization behavior test for JavaScript/Node.js
// Outputs JSON lines: {"test": "name", "result": "value"}
const tests = [
  // Float representation
  { test: "float_1e20", result: JSON.stringify(1e20) },
  { test: "float_1e-7", result: JSON.stringify(1e-7) },
  { test: "float_0.1+0.2", result: JSON.stringify(0.1 + 0.2) },
  { test: "float_min_positive", result: JSON.stringify(5e-324) },
  { test: "float_max", result: JSON.stringify(1.7976931348623157e+308) },
  { test: "float_subnormal", result: JSON.stringify(2.2250738585072014e-308) },

  // Integer edge cases
  { test: "negative_zero", result: JSON.stringify(-0) },
  { test: "int_2pow53_plus1", result: JSON.stringify(9007199254740993) },
  { test: "int_max_safe", result: JSON.stringify(9007199254740991) },
  { test: "int_negative_large", result: JSON.stringify(-9007199254740991) },

  // String escaping
  { test: "control_char_u0001", result: JSON.stringify({ a: "\x01" }) },
  { test: "control_char_u001f", result: JSON.stringify({ a: "\x1f" }) },
  { test: "slash", result: JSON.stringify("a/b") },
  { test: "backslash", result: JSON.stringify("a\\b") },
  { test: "angle_brackets", result: JSON.stringify("<script>") },
  { test: "ampersand", result: JSON.stringify("a&b") },
  { test: "tab_newline", result: JSON.stringify("line1\t\nline2") },
  { test: "null_byte", result: JSON.stringify("\x00") },

  // Unicode
  { test: "unicode_nfc", result: JSON.stringify("café") },
  { test: "unicode_nfd", result: JSON.stringify("café") },
  { test: "unicode_astral", result: JSON.stringify("\u{1F600}") },
  { test: "unicode_bmp_escape", result: JSON.stringify(" ") },
  { test: "unicode_surrogate_pair", result: JSON.stringify("😀") },

  // Object structure
  { test: "key_order_ba", result: JSON.stringify({ b: 1, a: 2 }) },
  { test: "key_numeric_strings", result: JSON.stringify({ "2": "b", "1": "a", "10": "c" }) },
  { test: "nested_depth", result: JSON.stringify({ a: { b: { c: { d: 1 } } } }) },
  { test: "empty_nested", result: JSON.stringify({ a: {}, b: [] }) },

  // MCP-specific protocol structures
  { test: "null_value", result: JSON.stringify({ name: "tool", arguments: null }) },
  { test: "empty_object", result: JSON.stringify({ name: "tool", arguments: {} }) },
  { test: "absent_key", result: JSON.stringify({ name: "tool" }) },
  { test: "isError_false", result: JSON.stringify({ content: [], isError: false }) },
  { test: "isError_absent", result: JSON.stringify({ content: [] }) },
  { test: "id_integer", result: JSON.stringify({ jsonrpc: "2.0", id: 1 }) },
  { test: "id_string", result: JSON.stringify({ jsonrpc: "2.0", id: "1" }) },

  // Boolean and null handling
  { test: "bool_false_vs_null", result: JSON.stringify({ a: false, b: null, c: 0, d: "" }) },
  { test: "empty_string_key", result: JSON.stringify({ "": "empty" }) },
  { test: "array_with_nulls", result: JSON.stringify([1, null, "three", null, 5]) },

  // Deeply nested MCP-like structures
  { test: "tool_with_schema", result: JSON.stringify({
    name: "get_weather",
    description: "Get weather for a location",
    inputSchema: {
      type: "object",
      properties: {
        location: { type: "string", description: "City name" },
        units: { type: "string", enum: ["celsius", "fahrenheit"], default: "celsius" }
      },
      required: ["location"]
    }
  })},
  { test: "content_array_mixed", result: JSON.stringify({
    content: [
      { type: "text", text: "Hello" },
      { type: "image", data: "base64...", mimeType: "image/png" }
    ]
  })},
  { test: "error_response", result: JSON.stringify({
    jsonrpc: "2.0", id: 1,
    error: { code: -32602, message: "Invalid params", data: { param: "missing_field" } }
  })},
];

for (const t of tests) {
  console.log(JSON.stringify(t));
}

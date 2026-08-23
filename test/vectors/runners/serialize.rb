#!/usr/bin/env ruby
# Serialization behavior test for Ruby.
require 'json'

tests = [
  # Float representation
  { test: "float_1e20", result: JSON.generate(1e20) },
  { test: "float_1e-7", result: JSON.generate(1e-7) },
  { test: "float_0.1+0.2", result: JSON.generate(0.1 + 0.2) },
  { test: "float_min_positive", result: JSON.generate(5e-324) },
  { test: "float_max", result: JSON.generate(1.7976931348623157e+308) },
  { test: "float_subnormal", result: JSON.generate(2.2250738585072014e-308) },

  # Integer edge cases
  { test: "negative_zero", result: JSON.generate(-0.0) },
  { test: "int_2pow53_plus1", result: JSON.generate(9007199254740993) },
  { test: "int_max_safe", result: JSON.generate(9007199254740991) },
  { test: "int_negative_large", result: JSON.generate(-9007199254740991) },

  # String escaping
  { test: "control_char_u0001", result: JSON.generate({ a: "\x01" }) },
  { test: "control_char_u001f", result: JSON.generate({ a: "\x1f" }) },
  { test: "slash", result: JSON.generate("a/b") },
  { test: "backslash", result: JSON.generate("a\\b") },
  { test: "angle_brackets", result: JSON.generate("<script>") },
  { test: "ampersand", result: JSON.generate("a&b") },
  { test: "tab_newline", result: JSON.generate("line1\t\nline2") },
  { test: "null_byte", result: JSON.generate("\x00") },

  # Unicode
  { test: "unicode_nfc", result: JSON.generate("café") },
  { test: "unicode_nfd", result: JSON.generate("café") },
  { test: "unicode_astral", result: JSON.generate("\u{1F600}") },
  { test: "unicode_bmp_escape", result: JSON.generate(" ") },
  { test: "unicode_surrogate_pair", result: JSON.generate("\u{1F600}") },

  # Object structure
  { test: "key_order_ba", result: JSON.generate({ b: 1, a: 2 }) },
  { test: "key_numeric_strings", result: JSON.generate({ "2" => "b", "1" => "a", "10" => "c" }) },
  { test: "nested_depth", result: JSON.generate({ a: { b: { c: { d: 1 } } } }) },
  { test: "empty_nested", result: JSON.generate({ a: {}, b: [] }) },

  # MCP-specific protocol structures
  { test: "null_value", result: JSON.generate({ name: "tool", arguments: nil }) },
  { test: "empty_object", result: JSON.generate({ name: "tool", arguments: {} }) },
  { test: "absent_key", result: JSON.generate({ name: "tool" }) },
  { test: "isError_false", result: JSON.generate({ content: [], isError: false }) },
  { test: "isError_absent", result: JSON.generate({ content: [] }) },
  { test: "id_integer", result: JSON.generate({ jsonrpc: "2.0", id: 1 }) },
  { test: "id_string", result: JSON.generate({ jsonrpc: "2.0", id: "1" }) },

  # Boolean and null handling
  { test: "bool_false_vs_null", result: JSON.generate({ a: false, b: nil, c: 0, d: "" }) },
  { test: "empty_string_key", result: JSON.generate({ "" => "empty" }) },
  { test: "array_with_nulls", result: JSON.generate([1, nil, "three", nil, 5]) },

  # Deeply nested MCP-like structures
  { test: "tool_with_schema", result: JSON.generate({
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
  { test: "content_array_mixed", result: JSON.generate({
    content: [
      { type: "text", text: "Hello" },
      { type: "image", data: "base64...", mimeType: "image/png" }
    ]
  })},
  { test: "error_response", result: JSON.generate({
    jsonrpc: "2.0", id: 1,
    error: { code: -32602, message: "Invalid params", data: { param: "missing_field" } }
  })},
]

tests.each { |t| puts JSON.generate(t) }

package main

// SDK-level serialization test for Go.
// Matches the Go MCP SDK's actual wire format:
// - Uses json.NewEncoder with SetEscapeHTML(false)
//   (see go-sdk@v1.6.1/internal/jsonrpc2/messages.go)
// Compare with serialize.go which uses default json.Marshal.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
)

type result struct {
	Test   string `json:"test"`
	Result string `json:"result"`
}

func serialize(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	// Encode adds a trailing newline; trim it
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return string(b)
}

func orderedObj(pairs ...interface{}) string {
	s := "{"
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			s += ","
		}
		key := serializeVal(pairs[i].(string))
		val := serializeVal(pairs[i+1])
		s += key + ":" + val
	}
	s += "}"
	return s
}

func serializeVal(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return string(b)
}

func main() {
	tests := []result{
		// Float representation
		{"float_1e20", serialize(1e20)},
		{"float_1e-7", serialize(1e-7)},
		{"float_0.1+0.2", serialize(0.1 + 0.2)},
		{"float_min_positive", serialize(5e-324)},
		{"float_max", serialize(1.7976931348623157e+308)},
		{"float_subnormal", serialize(2.2250738585072014e-308)},

		// Integer edge cases
		{"negative_zero", serialize(math.Copysign(0, -1))},
		{"int_2pow53_plus1", serialize(int64(9007199254740993))},
		{"int_max_safe", serialize(int64(9007199254740991))},
		{"int_negative_large", serialize(int64(-9007199254740991))},

		// String escaping
		{"control_char_u0001", serialize(map[string]string{"a": "\x01"})},
		{"control_char_u001f", serialize(map[string]string{"a": "\x1f"})},
		{"slash", serialize("a/b")},
		{"backslash", serialize("a\\b")},
		{"angle_brackets", serialize("<script>")},
		{"ampersand", serialize("a&b")},
		{"tab_newline", serialize("line1\t\nline2")},
		{"null_byte", serialize("\x00")},

		// Unicode
		{"unicode_nfc", serialize("café")},
		{"unicode_nfd", serialize("café")},
		{"unicode_astral", serialize("😀")},
		{"unicode_bmp_escape", serialize(" ")},
		{"unicode_surrogate_pair", serialize("😀")},

		// Object structure (Go SDK still sorts map keys via encoding/json)
		{"key_order_ba", orderedObj("b", 1, "a", 2)},
		{"key_numeric_strings", orderedObj("2", "b", "1", "a", "10", "c")},
		{"nested_depth", serialize(map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c": map[string]interface{}{"d": 1}}}})},
		{"empty_nested", orderedObj("a", map[string]interface{}{}, "b", []interface{}{})},

		// MCP-specific protocol structures
		{"null_value", orderedObj("name", "tool", "arguments", nil)},
		{"empty_object", orderedObj("name", "tool", "arguments", map[string]interface{}{})},
		{"absent_key", serialize(map[string]interface{}{"name": "tool"})},
		{"isError_false", orderedObj("content", []interface{}{}, "isError", false)},
		{"isError_absent", serialize(map[string]interface{}{"content": []interface{}{}})},
		{"id_integer", orderedObj("jsonrpc", "2.0", "id", 1)},
		{"id_string", orderedObj("jsonrpc", "2.0", "id", "1")},

		// Boolean and null handling
		{"bool_false_vs_null", orderedObj("a", false, "b", nil, "c", 0, "d", "")},
		{"empty_string_key", serialize(map[string]string{"": "empty"})},
		{"array_with_nulls", serialize([]interface{}{1, nil, "three", nil, 5})},

		// Deeply nested MCP-like structures
		{"tool_with_schema", orderedObj(
			"name", "get_weather",
			"description", "Get weather for a location",
			"inputSchema", map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"location": map[string]interface{}{"type": "string", "description": "City name"},
					"units":    map[string]interface{}{"type": "string", "enum": []string{"celsius", "fahrenheit"}, "default": "celsius"},
				},
				"required": []string{"location"},
			},
		)},
		{"content_array_mixed", orderedObj(
			"content", []interface{}{
				map[string]interface{}{"type": "text", "text": "Hello"},
				map[string]interface{}{"type": "image", "data": "base64...", "mimeType": "image/png"},
			},
		)},
		{"error_response", orderedObj(
			"jsonrpc", "2.0", "id", 1,
			"error", map[string]interface{}{"code": -32602, "message": "Invalid params", "data": map[string]interface{}{"param": "missing_field"}},
		)},
	}

	for _, t := range tests {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.Encode(t)
		b := buf.Bytes()
		if len(b) > 0 && b[len(b)-1] == '\n' {
			b = b[:len(b)-1]
		}
		fmt.Println(string(b))
	}
}

#!/usr/bin/env python3
"""Serialization behavior test for Python."""
import json
import sys
import unicodedata

S = (",", ":")  # compact separators

tests = [
    # Float representation
    {"test": "float_1e20", "result": json.dumps(1e20)},
    {"test": "float_1e-7", "result": json.dumps(1e-7)},
    {"test": "float_0.1+0.2", "result": json.dumps(0.1 + 0.2)},
    {"test": "float_min_positive", "result": json.dumps(5e-324)},
    {"test": "float_max", "result": json.dumps(1.7976931348623157e+308)},
    {"test": "float_subnormal", "result": json.dumps(2.2250738585072014e-308)},

    # Integer edge cases
    {"test": "negative_zero", "result": json.dumps(-0.0)},
    {"test": "int_2pow53_plus1", "result": json.dumps(9007199254740993)},
    {"test": "int_max_safe", "result": json.dumps(9007199254740991)},
    {"test": "int_negative_large", "result": json.dumps(-9007199254740991)},

    # String escaping
    {"test": "control_char_u0001", "result": json.dumps({"a": "\x01"}, separators=S)},
    {"test": "control_char_u001f", "result": json.dumps({"a": "\x1f"}, separators=S)},
    {"test": "slash", "result": json.dumps("a/b")},
    {"test": "backslash", "result": json.dumps("a\\b")},
    {"test": "angle_brackets", "result": json.dumps("<script>")},
    {"test": "ampersand", "result": json.dumps("a&b")},
    {"test": "tab_newline", "result": json.dumps("line1\t\nline2")},
    {"test": "null_byte", "result": json.dumps("\x00")},

    # Unicode
    {"test": "unicode_nfc", "result": json.dumps(unicodedata.normalize("NFC", "café"))},
    {"test": "unicode_nfd", "result": json.dumps(unicodedata.normalize("NFD", "café"))},
    {"test": "unicode_astral", "result": json.dumps("\U0001F600")},
    {"test": "unicode_bmp_escape", "result": json.dumps(" ")},
    {"test": "unicode_surrogate_pair", "result": json.dumps("😀")},

    # Object structure
    {"test": "key_order_ba", "result": json.dumps({"b": 1, "a": 2}, separators=S)},
    {"test": "key_numeric_strings", "result": json.dumps({"2": "b", "1": "a", "10": "c"}, separators=S)},
    {"test": "nested_depth", "result": json.dumps({"a": {"b": {"c": {"d": 1}}}}, separators=S)},
    {"test": "empty_nested", "result": json.dumps({"a": {}, "b": []}, separators=S)},

    # MCP-specific protocol structures
    {"test": "null_value", "result": json.dumps({"name": "tool", "arguments": None}, separators=S)},
    {"test": "empty_object", "result": json.dumps({"name": "tool", "arguments": {}}, separators=S)},
    {"test": "absent_key", "result": json.dumps({"name": "tool"}, separators=S)},
    {"test": "isError_false", "result": json.dumps({"content": [], "isError": False}, separators=S)},
    {"test": "isError_absent", "result": json.dumps({"content": []}, separators=S)},
    {"test": "id_integer", "result": json.dumps({"jsonrpc": "2.0", "id": 1}, separators=S)},
    {"test": "id_string", "result": json.dumps({"jsonrpc": "2.0", "id": "1"}, separators=S)},

    # Boolean and null handling
    {"test": "bool_false_vs_null", "result": json.dumps({"a": False, "b": None, "c": 0, "d": ""}, separators=S)},
    {"test": "empty_string_key", "result": json.dumps({"": "empty"}, separators=S)},
    {"test": "array_with_nulls", "result": json.dumps([1, None, "three", None, 5], separators=S)},

    # Deeply nested MCP-like structures
    {"test": "tool_with_schema", "result": json.dumps({
        "name": "get_weather",
        "description": "Get weather for a location",
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"},
                "units": {"type": "string", "enum": ["celsius", "fahrenheit"], "default": "celsius"}
            },
            "required": ["location"]
        }
    }, separators=S)},
    {"test": "content_array_mixed", "result": json.dumps({
        "content": [
            {"type": "text", "text": "Hello"},
            {"type": "image", "data": "base64...", "mimeType": "image/png"}
        ]
    }, separators=S)},
    {"test": "error_response", "result": json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32602, "message": "Invalid params", "data": {"param": "missing_field"}}
    }, separators=S)},
]

for t in tests:
    print(json.dumps(t))

#!/usr/bin/env python3
# SDK-level serialization test for Python MCP SDK.
# Tests pydantic v2's model_dump_json() / TypeAdapter.dump_json()
# which is the ACTUAL serialization path used by the Python MCP SDK,
# NOT stdlib json.dumps (tested by serialize.py).
import json
import unicodedata
from pydantic import TypeAdapter

ta_dict = TypeAdapter(dict)
ta_list = TypeAdapter(list)
ta_str = TypeAdapter(str)
ta_float = TypeAdapter(float)
ta_int = TypeAdapter(int)

def ser_dict(v):
    return ta_dict.dump_json(v).decode()

def ser_list(v):
    return ta_list.dump_json(v).decode()

def ser_str(v):
    return ta_str.dump_json(v).decode()

def ser_float(v):
    return ta_float.dump_json(v).decode()

def ser_int(v):
    return ta_int.dump_json(v).decode()

def emit(test, result):
    print(json.dumps({"test": test, "result": result}, separators=(",", ":")))

# Float representation
emit("float_1e20", ser_float(1e20))
emit("float_1e-7", ser_float(1e-7))
emit("float_0.1+0.2", ser_float(0.1 + 0.2))
emit("float_min_positive", ser_float(5e-324))
emit("float_max", ser_float(1.7976931348623157e+308))
emit("float_subnormal", ser_float(2.2250738585072014e-308))

# Integer edge cases
emit("negative_zero", ser_float(-0.0))
emit("int_2pow53_plus1", ser_int(9007199254740993))
emit("int_max_safe", ser_int(9007199254740991))
emit("int_negative_large", ser_int(-9007199254740991))

# String escaping
emit("control_char_u0001", ser_dict({"a": "\x01"}))
emit("control_char_u001f", ser_dict({"a": "\x1f"}))
emit("slash", ser_str("a/b"))
emit("backslash", ser_str("a\\b"))
emit("angle_brackets", ser_str("<script>"))
emit("ampersand", ser_str("a&b"))
emit("tab_newline", ser_str("line1\t\nline2"))
emit("null_byte", ser_str("\x00"))

# Unicode
emit("unicode_nfc", ser_str("café"))
emit("unicode_nfd", ser_str(unicodedata.normalize("NFD", "café")))
emit("unicode_astral", ser_str("\U0001F600"))
emit("unicode_bmp_escape", ser_str(" "))
emit("unicode_surrogate_pair", ser_str("\U0001F600"))

# Object structure
emit("key_order_ba", ser_dict({"b": 1, "a": 2}))
emit("key_numeric_strings", ser_dict({"2": "b", "1": "a", "10": "c"}))
emit("nested_depth", ser_dict({"a": {"b": {"c": {"d": 1}}}}))
emit("empty_nested", ser_dict({"a": {}, "b": []}))

# MCP-specific protocol structures
emit("null_value", ser_dict({"name": "tool", "arguments": None}))
emit("empty_object", ser_dict({"name": "tool", "arguments": {}}))
emit("absent_key", ser_dict({"name": "tool"}))
emit("isError_false", ser_dict({"content": [], "isError": False}))
emit("isError_absent", ser_dict({"content": []}))
emit("id_integer", ser_dict({"jsonrpc": "2.0", "id": 1}))
emit("id_string", ser_dict({"jsonrpc": "2.0", "id": "1"}))

# Boolean and null handling
emit("bool_false_vs_null", ser_dict({"a": False, "b": None, "c": 0, "d": ""}))
emit("empty_string_key", ser_dict({"": "empty"}))
emit("array_with_nulls", ser_list([1, None, "three", None, 5]))

# Deeply nested MCP-like structures
emit("tool_with_schema", ser_dict({
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
}))
emit("content_array_mixed", ser_dict({
    "content": [
        {"type": "text", "text": "Hello"},
        {"type": "image", "data": "base64...", "mimeType": "image/png"}
    ]
}))
emit("error_response", ser_dict({
    "jsonrpc": "2.0", "id": 1,
    "error": {"code": -32602, "message": "Invalid params", "data": {"param": "missing_field"}}
}))

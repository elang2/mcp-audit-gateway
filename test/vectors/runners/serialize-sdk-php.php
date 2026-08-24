<?php
// SDK-level serialization test for PHP MCP SDK.
// Uses json_encode with JSON_THROW_ON_ERROR only,
// matching StdioTransport and StreamableHttpTransport.
// NOTE: StatelessResponder adds JSON_UNESCAPED_SLASHES (transport-level inconsistency).

$FLAGS = JSON_THROW_ON_ERROR;

function emit($test, $result) {
    echo json_encode(["test" => $test, "result" => $result], JSON_THROW_ON_ERROR) . "\n";
}

function ser_value($v) {
    global $FLAGS;
    return json_encode($v, $FLAGS);
}

// Float representation
emit("float_1e20", ser_value(1e20));
emit("float_1e-7", ser_value(1e-7));
emit("float_0.1+0.2", ser_value(0.1 + 0.2));
emit("float_min_positive", ser_value(5e-324));
emit("float_max", ser_value(1.7976931348623157e+308));
emit("float_subnormal", ser_value(2.2250738585072014e-308));

// Integer edge cases
emit("negative_zero", ser_value(-0.0));
emit("int_2pow53_plus1", ser_value(9007199254740993));
emit("int_max_safe", ser_value(9007199254740991));
emit("int_negative_large", ser_value(-9007199254740991));

// String escaping
emit("control_char_u0001", ser_value(["a" => "\x01"]));
emit("control_char_u001f", ser_value(["a" => "\x1f"]));
emit("slash", ser_value("a/b"));
emit("backslash", ser_value("a\\b"));
emit("angle_brackets", ser_value("<script>"));
emit("ampersand", ser_value("a&b"));
emit("tab_newline", ser_value("line1\t\nline2"));
emit("null_byte", ser_value("\x00"));

// Unicode
emit("unicode_nfc", ser_value("café"));
emit("unicode_nfd", ser_value("cafe\xCC\x81"));
emit("unicode_astral", ser_value("\xF0\x9F\x98\x80"));
emit("unicode_bmp_escape", ser_value(" "));
emit("unicode_surrogate_pair", ser_value("\xF0\x9F\x98\x80"));

// Object structure
emit("key_order_ba", ser_value(["b" => 1, "a" => 2]));
emit("key_numeric_strings", ser_value(["2" => "b", "1" => "a", "10" => "c"]));
emit("nested_depth", ser_value(["a" => ["b" => ["c" => ["d" => 1]]]]));
emit("empty_nested", ser_value(["a" => new stdClass(), "b" => []]));

// MCP-specific protocol structures
emit("null_value", ser_value(["name" => "tool", "arguments" => null]));
emit("empty_object", ser_value(["name" => "tool", "arguments" => new stdClass()]));
emit("absent_key", ser_value(["name" => "tool"]));
emit("isError_false", ser_value(["content" => [], "isError" => false]));
emit("isError_absent", ser_value(["content" => []]));
emit("id_integer", ser_value(["jsonrpc" => "2.0", "id" => 1]));
emit("id_string", ser_value(["jsonrpc" => "2.0", "id" => "1"]));

// Boolean and null handling
emit("bool_false_vs_null", ser_value(["a" => false, "b" => null, "c" => 0, "d" => ""]));
emit("empty_string_key", ser_value(["" => "empty"]));
emit("array_with_nulls", ser_value([1, null, "three", null, 5]));

// Complex structures
emit("tool_with_schema", ser_value([
    "name" => "get_weather",
    "description" => "Get weather for a location",
    "inputSchema" => [
        "type" => "object",
        "properties" => [
            "location" => ["type" => "string", "description" => "City name"],
            "units" => ["type" => "string", "enum" => ["celsius", "fahrenheit"], "default" => "celsius"]
        ],
        "required" => ["location"]
    ]
]));
emit("content_array_mixed", ser_value([
    "content" => [
        ["type" => "text", "text" => "Hello"],
        ["type" => "image", "data" => "base64...", "mimeType" => "image/png"]
    ]
]));
emit("error_response", ser_value([
    "jsonrpc" => "2.0", "id" => 1,
    "error" => ["code" => -32602, "message" => "Invalid params", "data" => ["param" => "missing_field"]]
]));

#!/usr/bin/env php
<?php
// Serialization behavior test for PHP.

$tests = [
    // Float representation
    ["test" => "float_1e20", "result" => json_encode(1e20)],
    ["test" => "float_1e-7", "result" => json_encode(1e-7)],
    ["test" => "float_0.1+0.2", "result" => json_encode(0.1 + 0.2)],
    ["test" => "float_min_positive", "result" => json_encode(5e-324)],
    ["test" => "float_max", "result" => json_encode(1.7976931348623157e+308)],
    ["test" => "float_subnormal", "result" => json_encode(2.2250738585072014e-308)],

    // Integer edge cases
    ["test" => "negative_zero", "result" => json_encode(-0.0)],
    ["test" => "int_2pow53_plus1", "result" => json_encode(9007199254740993)],
    ["test" => "int_max_safe", "result" => json_encode(9007199254740991)],
    ["test" => "int_negative_large", "result" => json_encode(-9007199254740991)],

    // String escaping
    ["test" => "control_char_u0001", "result" => json_encode(["a" => "\x01"])],
    ["test" => "control_char_u001f", "result" => json_encode(["a" => "\x1f"])],
    ["test" => "slash", "result" => json_encode("a/b", JSON_UNESCAPED_SLASHES)],
    ["test" => "backslash", "result" => json_encode("a\\b")],
    ["test" => "angle_brackets", "result" => json_encode("<script>", JSON_UNESCAPED_UNICODE)],
    ["test" => "ampersand", "result" => json_encode("a&b")],
    ["test" => "tab_newline", "result" => json_encode("line1\t\nline2")],
    ["test" => "null_byte", "result" => json_encode("\x00")],

    // Unicode
    ["test" => "unicode_nfc", "result" => json_encode("café", JSON_UNESCAPED_UNICODE)],
    ["test" => "unicode_nfd", "result" => json_encode(Normalizer::normalize("café", Normalizer::FORM_D), JSON_UNESCAPED_UNICODE)],
    ["test" => "unicode_astral", "result" => json_encode("\xF0\x9F\x98\x80", JSON_UNESCAPED_UNICODE)],
    ["test" => "unicode_bmp_escape", "result" => json_encode("\xC2\xA0", JSON_UNESCAPED_UNICODE)],
    ["test" => "unicode_surrogate_pair", "result" => json_encode("\xF0\x9F\x98\x80", JSON_UNESCAPED_UNICODE)],

    // Object structure
    ["test" => "key_order_ba", "result" => json_encode(["b" => 1, "a" => 2])],
    ["test" => "key_numeric_strings", "result" => json_encode(["2" => "b", "1" => "a", "10" => "c"])],
    ["test" => "nested_depth", "result" => json_encode(["a" => ["b" => ["c" => ["d" => 1]]]])],
    ["test" => "empty_nested", "result" => json_encode(["a" => new stdClass(), "b" => []])],

    // MCP-specific protocol structures
    ["test" => "null_value", "result" => json_encode(["name" => "tool", "arguments" => null])],
    ["test" => "empty_object", "result" => json_encode(["name" => "tool", "arguments" => new stdClass()])],
    ["test" => "absent_key", "result" => json_encode(["name" => "tool"])],
    ["test" => "isError_false", "result" => json_encode(["content" => [], "isError" => false])],
    ["test" => "isError_absent", "result" => json_encode(["content" => []])],
    ["test" => "id_integer", "result" => json_encode(["jsonrpc" => "2.0", "id" => 1])],
    ["test" => "id_string", "result" => json_encode(["jsonrpc" => "2.0", "id" => "1"])],

    // Boolean and null handling
    ["test" => "bool_false_vs_null", "result" => json_encode(["a" => false, "b" => null, "c" => 0, "d" => ""])],
    ["test" => "empty_string_key", "result" => json_encode(["" => "empty"])],
    ["test" => "array_with_nulls", "result" => json_encode([1, null, "three", null, 5])],

    // Deeply nested MCP-like structures
    ["test" => "tool_with_schema", "result" => json_encode([
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
    ])],
    ["test" => "content_array_mixed", "result" => json_encode([
        "content" => [
            ["type" => "text", "text" => "Hello"],
            ["type" => "image", "data" => "base64...", "mimeType" => "image/png"]
        ]
    ])],
    ["test" => "error_response", "result" => json_encode([
        "jsonrpc" => "2.0", "id" => 1,
        "error" => ["code" => -32602, "message" => "Invalid params", "data" => ["param" => "missing_field"]]
    ])],
];

foreach ($tests as $t) {
    echo json_encode($t) . "\n";
}

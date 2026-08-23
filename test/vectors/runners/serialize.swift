import Foundation

struct TestResult: Codable {
    let test: String
    let result: String
}

func serialize(_ value: Any) -> String {
    // .sortedKeys used for deterministic output (Swift Dictionaries are unordered)
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])
    return String(data: data, encoding: .utf8)!
}

func serializeValue(_ value: Any) -> String {
    let data = try! JSONSerialization.data(withJSONObject: [value], options: [.fragmentsAllowed])
    let str = String(data: data, encoding: .utf8)!
    // Strip wrapping array brackets
    let inner = String(str.dropFirst().dropLast())
    return inner
}

func serializeArray(_ value: [Any]) -> String {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
    return String(data: data, encoding: .utf8)!
}

let tests: [(String, String)] = [
    // Float representation
    ("float_1e20", serializeValue(1e20)),
    ("float_1e-7", serializeValue(1e-7)),
    ("float_0.1+0.2", serializeValue(0.1 + 0.2)),
    ("float_min_positive", serializeValue(5e-324)),
    ("float_max", serializeValue(1.7976931348623157e+308)),
    ("float_subnormal", serializeValue(2.2250738585072014e-308)),

    // Integer edge cases
    ("negative_zero", serializeValue(-0.0)),
    ("int_2pow53_plus1", serializeValue(9007199254740993)),
    ("int_max_safe", serializeValue(9007199254740991)),
    ("int_negative_large", serializeValue(-9007199254740991)),

    // String escaping
    ("control_char_u0001", serialize(["a": "\u{0001}"])),
    ("control_char_u001f", serialize(["a": "\u{001f}"])),
    ("slash", serializeValue("a/b")),
    ("backslash", serializeValue("a\\b")),
    ("angle_brackets", serializeValue("<script>")),
    ("ampersand", serializeValue("a&b")),
    ("tab_newline", serializeValue("line1\t\nline2")),
    ("null_byte", serializeValue("\u{0000}")),

    // Unicode
    ("unicode_nfc", serializeValue("caf\u{00e9}")),
    ("unicode_nfd", serializeValue(("café" as NSString).decomposedStringWithCanonicalMapping)),
    ("unicode_astral", serializeValue("\u{1F600}")),
    ("unicode_bmp_escape", serializeValue(" ")),
    ("unicode_surrogate_pair", serializeValue("😀")),

    // Object structure
    ("key_order_ba", serialize(["b": 1, "a": 2])),
    ("key_numeric_strings", serialize(["2": "b", "1": "a", "10": "c"])),
    ("nested_depth", serialize(["a": ["b": ["c": ["d": 1]]]])),
    ("empty_nested", serialize(["a": [:] as [String: Any], "b": [] as [Any]] as [String: Any])),

    // MCP-specific protocol structures
    ("null_value", serialize(["name": "tool", "arguments": NSNull()] as [String: Any])),
    ("empty_object", serialize(["name": "tool", "arguments": [:] as [String: Any]] as [String: Any])),
    ("absent_key", serialize(["name": "tool"])),
    ("isError_false", serialize(["content": [] as [Any], "isError": false] as [String: Any])),
    ("isError_absent", serialize(["content": [] as [Any]] as [String: Any])),
    ("id_integer", serialize(["jsonrpc": "2.0", "id": 1] as [String: Any])),
    ("id_string", serialize(["jsonrpc": "2.0", "id": "1"] as [String: Any])),

    // Boolean and null handling
    ("bool_false_vs_null", serialize(["a": false, "b": NSNull(), "c": 0, "d": ""] as [String: Any])),
    ("empty_string_key", serialize(["": "empty"])),
    ("array_with_nulls", serializeArray([1, NSNull(), "three", NSNull(), 5] as [Any])),

    // Deeply nested MCP-like structures
    ("tool_with_schema", serialize([
        "name": "get_weather",
        "description": "Get weather for a location",
        "inputSchema": [
            "type": "object",
            "properties": [
                "location": ["type": "string", "description": "City name"] as [String: Any],
                "units": ["type": "string", "enum": ["celsius", "fahrenheit"], "default": "celsius"] as [String: Any]
            ] as [String: Any],
            "required": ["location"]
        ] as [String: Any]
    ] as [String: Any])),
    ("content_array_mixed", serialize([
        "content": [
            ["type": "text", "text": "Hello"] as [String: Any],
            ["type": "image", "data": "base64...", "mimeType": "image/png"] as [String: Any]
        ]
    ] as [String: Any])),
    ("error_response", serialize([
        "jsonrpc": "2.0", "id": 1,
        "error": ["code": -32602, "message": "Invalid params", "data": ["param": "missing_field"] as [String: Any]] as [String: Any]
    ] as [String: Any])),
]

let encoder = JSONEncoder()
for (name, result) in tests {
    let t = TestResult(test: name, result: result)
    let data = try! encoder.encode(t)
    print(String(data: data, encoding: .utf8)!)
}

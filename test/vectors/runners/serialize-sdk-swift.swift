#!/usr/bin/env swift
// SDK-level serialization test for Swift MCP SDK (SERVER side).
// Uses JSONEncoder with .sortedKeys and .withoutEscapingSlashes,
// matching the configuration in swift-sdk/Sources/MCP/Server/Server.swift.
// The Swift MCP Client uses bare JSONEncoder() (different behavior!).
import Foundation

func emit(_ test: String, _ result: String) {
    // Output format: {"test":"<name>","result":"<json-serialized-value>"}
    // result is already a JSON string (the serialized form of the test value)
    let escaped = result
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\t", with: "\\t")
        .replacingOccurrences(of: "\r", with: "\\r")
    print("{\"test\":\"\(test)\",\"result\":\"\(escaped)\"}")
}

// SDK Server configuration: .sortedKeys + .withoutEscapingSlashes
func serDict(_ v: [String: Any]) -> String {
    var opts: JSONSerialization.WritingOptions = [.sortedKeys, .fragmentsAllowed]
    if #available(macOS 13.0, iOS 16.0, *) {
        opts.insert(.withoutEscapingSlashes)
    }
    let data = try! JSONSerialization.data(withJSONObject: v, options: opts)
    return String(data: data, encoding: .utf8)!
}

func serList(_ v: [Any]) -> String {
    var opts: JSONSerialization.WritingOptions = [.sortedKeys, .fragmentsAllowed]
    if #available(macOS 13.0, iOS 16.0, *) {
        opts.insert(.withoutEscapingSlashes)
    }
    let data = try! JSONSerialization.data(withJSONObject: v, options: opts)
    return String(data: data, encoding: .utf8)!
}

func serString(_ v: String) -> String {
    var opts: JSONSerialization.WritingOptions = [.fragmentsAllowed]
    if #available(macOS 13.0, iOS 16.0, *) {
        opts.insert(.withoutEscapingSlashes)
    }
    let data = try! JSONSerialization.data(withJSONObject: v, options: opts)
    return String(data: data, encoding: .utf8)!
}

func serFloat(_ v: Double) -> String {
    var opts: JSONSerialization.WritingOptions = [.fragmentsAllowed]
    if #available(macOS 13.0, iOS 16.0, *) {
        opts.insert(.withoutEscapingSlashes)
    }
    let data = try! JSONSerialization.data(withJSONObject: v, options: opts)
    return String(data: data, encoding: .utf8)!
}

func serInt(_ v: Int) -> String {
    let data = try! JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed])
    return String(data: data, encoding: .utf8)!
}

// Float representation
emit("float_1e20", serFloat(1e20))
emit("float_1e-7", serFloat(1e-7))
emit("float_0.1+0.2", serFloat(0.1 + 0.2))
emit("float_min_positive", serFloat(5e-324))
emit("float_max", serFloat(1.7976931348623157e+308))
emit("float_subnormal", serFloat(2.2250738585072014e-308))

// Integer edge cases
emit("negative_zero", serFloat(-0.0))
emit("int_2pow53_plus1", serInt(9007199254740993))
emit("int_max_safe", serInt(9007199254740991))
emit("int_negative_large", serInt(-9007199254740991))

// String escaping
emit("control_char_u0001", serDict(["a": "\u{01}"]))
emit("control_char_u001f", serDict(["a": "\u{1f}"]))
emit("slash", serString("a/b"))
emit("backslash", serString("a\\b"))
emit("angle_brackets", serString("<script>"))
emit("ampersand", serString("a&b"))
emit("tab_newline", serString("line1\t\nline2"))
emit("null_byte", serString("\u{00}"))

// Unicode
emit("unicode_nfc", serString("caf\u{e9}"))
emit("unicode_nfd", serString("cafe\u{0301}"))
emit("unicode_astral", serString("\u{1F600}"))
emit("unicode_bmp_escape", serString("\u{00a0}"))
emit("unicode_surrogate_pair", serString("\u{1F600}"))

// Object structure (sortedKeys = keys alphabetized)
emit("key_order_ba", serDict(["b": 1, "a": 2]))
emit("key_numeric_strings", serDict(["2": "b", "1": "a", "10": "c"]))
emit("nested_depth", serDict(["a": ["b": ["c": ["d": 1]]]]))
emit("empty_nested", serDict(["a": [String: Any](), "b": [Any]()]))

// MCP-specific protocol structures
emit("null_value", serDict(["name": "tool", "arguments": NSNull()]))
emit("empty_object", serDict(["name": "tool", "arguments": [String: Any]()]))
emit("absent_key", serDict(["name": "tool"]))
emit("isError_false", serDict(["content": [Any](), "isError": false]))
emit("isError_absent", serDict(["content": [Any]()]))
emit("id_integer", serDict(["jsonrpc": "2.0", "id": 1]))
emit("id_string", serDict(["jsonrpc": "2.0", "id": "1"]))

// Boolean and null handling
emit("bool_false_vs_null", serDict(["a": false, "b": NSNull(), "c": 0, "d": ""]))
emit("empty_string_key", serDict(["": "empty"]))
emit("array_with_nulls", serList([1, NSNull(), "three", NSNull(), 5]))

// Complex structures
emit("tool_with_schema", serDict([
    "name": "get_weather",
    "description": "Get weather for a location",
    "inputSchema": [
        "type": "object",
        "properties": [
            "location": ["type": "string", "description": "City name"],
            "units": ["type": "string", "enum": ["celsius", "fahrenheit"], "default": "celsius"]
        ] as [String: Any],
        "required": ["location"]
    ] as [String: Any]
] as [String: Any]))
emit("content_array_mixed", serDict([
    "content": [
        ["type": "text", "text": "Hello"],
        ["type": "image", "data": "base64...", "mimeType": "image/png"]
    ]
] as [String: Any]))
emit("error_response", serDict([
    "jsonrpc": "2.0", "id": 1,
    "error": ["code": -32602, "message": "Invalid params", "data": ["param": "missing_field"]]
] as [String: Any]))

// Serialization behavior test for C#.
// Run: dotnet-script serialize.cs
// Or: dotnet run (with a .csproj)
using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Collections.Generic;

var options = new JsonSerializerOptions { WriteIndented = false };

void Emit(string test, string result) {
    var obj = new JsonObject { ["test"] = test, ["result"] = result };
    Console.WriteLine(obj.ToJsonString());
}

string Serialize(object value) => JsonSerializer.Serialize(value, options);

Emit("float_1e20", Serialize(1e20));
Emit("float_1e-7", Serialize(1e-7));
Emit("float_0.1+0.2", Serialize(0.1 + 0.2));
Emit("float_min_positive", Serialize(5e-324));
Emit("float_max", Serialize(1.7976931348623157e+308));
Emit("float_subnormal", Serialize(2.2250738585072014e-308));
Emit("negative_zero", Serialize(-0.0));
Emit("int_2pow53_plus1", Serialize(9007199254740993L));
Emit("int_max_safe", Serialize(9007199254740991L));
Emit("int_negative_large", Serialize(-9007199254740991L));
Emit("control_char_u0001", Serialize(new Dictionary<string, string> { ["a"] = "\x01" }));
Emit("control_char_u001f", Serialize(new Dictionary<string, string> { ["a"] = "\x1f" }));
Emit("slash", Serialize("a/b"));
Emit("backslash", Serialize("a\\b"));
Emit("angle_brackets", Serialize("<script>"));
Emit("ampersand", Serialize("a&b"));
Emit("tab_newline", Serialize("line1\t\nline2"));
Emit("null_byte", Serialize("\x00"));
Emit("unicode_nfc", Serialize("café"));
Emit("unicode_nfd", Serialize("café"));
Emit("unicode_astral", Serialize("\U0001F600"));
Emit("unicode_bmp_escape", Serialize(" "));
Emit("unicode_surrogate_pair", Serialize("\U0001F600"));
Emit("key_order_ba", Serialize(new Dictionary<string, int> { ["b"] = 1, ["a"] = 2 }));
Emit("key_numeric_strings", Serialize(new Dictionary<string, string> { ["2"] = "b", ["1"] = "a", ["10"] = "c" }));
Emit("nested_depth", Serialize(new { a = new { b = new { c = new { d = 1 } } } }));
Emit("empty_nested", Serialize(new { a = new { }, b = Array.Empty<object>() }));
Emit("null_value", "{\"name\":\"tool\",\"arguments\":null}");
Emit("empty_object", "{\"name\":\"tool\",\"arguments\":{}}");
Emit("absent_key", Serialize(new { name = "tool" }));
Emit("isError_false", Serialize(new { content = Array.Empty<object>(), isError = false }));
Emit("isError_absent", Serialize(new { content = Array.Empty<object>() }));
Emit("id_integer", Serialize(new { jsonrpc = "2.0", id = 1 }));
Emit("id_string", Serialize(new { jsonrpc = "2.0", id = "1" }));
Emit("bool_false_vs_null", "{\"a\":false,\"b\":null,\"c\":0,\"d\":\"\"}");
Emit("empty_string_key", Serialize(new Dictionary<string, string> { [""] = "empty" }));
Emit("array_with_nulls", Serialize(new object[] { 1, null, "three", null, 5 }));
Emit("tool_with_schema", "{\"name\":\"get_weather\",\"description\":\"Get weather for a location\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"location\":{\"type\":\"string\",\"description\":\"City name\"},\"units\":{\"type\":\"string\",\"enum\":[\"celsius\",\"fahrenheit\"],\"default\":\"celsius\"}},\"required\":[\"location\"]}}");
Emit("content_array_mixed", "{\"content\":[{\"type\":\"text\",\"text\":\"Hello\"},{\"type\":\"image\",\"data\":\"base64...\",\"mimeType\":\"image/png\"}]}");
Emit("error_response", "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\",\"data\":{\"param\":\"missing_field\"}}}");

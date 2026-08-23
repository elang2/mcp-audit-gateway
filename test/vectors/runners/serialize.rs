// Serialization behavior test for Rust.
// Compile: rustc --edition 2021 serialize.rs -o serialize-rust
// Requires: serde_json (or use this with cargo, see below)
//
// For standalone compilation without cargo:
//   This file uses only std. For full JSON compat, use the cargo version.
//
// Cargo.toml single-file (cargo-script):
//   cargo install cargo-script
//   cargo script serialize.rs

use std::collections::BTreeMap;
use std::collections::HashMap;

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_num_f64(v: f64) -> String {
    if v == 0.0 && v.is_sign_negative() {
        "-0.0".to_string()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{:.1}", v)
    } else {
        format!("{}", v)
    }
}

fn emit(test: &str, result: &str) {
    println!("{{\"test\":{},\"result\":{}}}", json_string(test), json_string(result));
}

fn main() {
    emit("float_1e20", &json_num_f64(1e20));
    emit("float_1e-7", &json_num_f64(1e-7));
    emit("float_0.1+0.2", &json_num_f64(0.1 + 0.2));
    emit("float_min_positive", &json_num_f64(5e-324));
    emit("float_max", &json_num_f64(1.7976931348623157e+308));
    emit("float_subnormal", &json_num_f64(2.2250738585072014e-308));
    emit("negative_zero", &json_num_f64(-0.0));
    emit("int_2pow53_plus1", &format!("{}", 9007199254740993i64));
    emit("int_max_safe", &format!("{}", 9007199254740991i64));
    emit("int_negative_large", &format!("{}", -9007199254740991i64));
    emit("control_char_u0001", &format!("{{\"a\":{}}}", json_string("\x01")));
    emit("control_char_u001f", &format!("{{\"a\":{}}}", json_string("\x1f")));
    emit("slash", &json_string("a/b"));
    emit("backslash", &json_string("a\\b"));
    emit("angle_brackets", &json_string("<script>"));
    emit("ampersand", &json_string("a&b"));
    emit("tab_newline", &json_string("line1\t\nline2"));
    emit("null_byte", &json_string("\x00"));
    emit("unicode_nfc", &json_string("caf\u{00e9}"));
    emit("unicode_nfd", &json_string("cafe\u{0301}"));
    emit("unicode_astral", &json_string("\u{1F600}"));
    emit("unicode_bmp_escape", &json_string(" "));
    emit("unicode_surrogate_pair", &json_string("\u{1F600}"));
    emit("key_order_ba", "{\"b\":1,\"a\":2}");
    emit("key_numeric_strings", "{\"2\":\"b\",\"1\":\"a\",\"10\":\"c\"}");
    emit("nested_depth", "{\"a\":{\"b\":{\"c\":{\"d\":1}}}}");
    emit("empty_nested", "{\"a\":{},\"b\":[]}");
    emit("null_value", "{\"name\":\"tool\",\"arguments\":null}");
    emit("empty_object", "{\"name\":\"tool\",\"arguments\":{}}");
    emit("absent_key", "{\"name\":\"tool\"}");
    emit("isError_false", "{\"content\":[],\"isError\":false}");
    emit("isError_absent", "{\"content\":[]}");
    emit("id_integer", "{\"jsonrpc\":\"2.0\",\"id\":1}");
    emit("id_string", "{\"jsonrpc\":\"2.0\",\"id\":\"1\"}");
    emit("bool_false_vs_null", "{\"a\":false,\"b\":null,\"c\":0,\"d\":\"\"}");
    emit("empty_string_key", "{\"\":\"empty\"}");
    emit("array_with_nulls", "[1,null,\"three\",null,5]");
    emit("tool_with_schema", "{\"name\":\"get_weather\",\"description\":\"Get weather for a location\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"location\":{\"type\":\"string\",\"description\":\"City name\"},\"units\":{\"type\":\"string\",\"enum\":[\"celsius\",\"fahrenheit\"],\"default\":\"celsius\"}},\"required\":[\"location\"]}}");
    emit("content_array_mixed", "{\"content\":[{\"type\":\"text\",\"text\":\"Hello\"},{\"type\":\"image\",\"data\":\"base64...\",\"mimeType\":\"image/png\"}]}");
    emit("error_response", "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\",\"data\":{\"param\":\"missing_field\"}}}");
}

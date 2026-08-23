#!/usr/bin/env perl
# Serialization behavior test for Perl.
use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';
use JSON::PP;

my $json = JSON::PP->new->canonical(0)->allow_nonref;
my $json_out = JSON::PP->new->canonical(1)->allow_nonref;

sub emit {
    my ($test, $result) = @_;
    print $json_out->encode({ result => $result, test => $test }) . "\n";
}

# Float representation
emit("float_1e20", $json->encode(1e20));
emit("float_1e-7", $json->encode(1e-7));
emit("float_0.1+0.2", $json->encode(0.1 + 0.2));
emit("float_min_positive", $json->encode(5e-324));
emit("float_max", $json->encode(1.7976931348623157e+308));
emit("float_subnormal", $json->encode(2.2250738585072014e-308));

# Integer edge cases
emit("negative_zero", $json->encode(-0.0));
emit("int_2pow53_plus1", $json->encode(9007199254740993));
emit("int_max_safe", $json->encode(9007199254740991));
emit("int_negative_large", $json->encode(-9007199254740991));

# String escaping
emit("control_char_u0001", $json->encode({ a => "\x01" }));
emit("control_char_u001f", $json->encode({ a => "\x1f" }));
emit("slash", $json->encode("a/b"));
emit("backslash", $json->encode("a\\b"));
emit("angle_brackets", $json->encode("<script>"));
emit("ampersand", $json->encode("a&b"));
emit("tab_newline", $json->encode("line1\t\nline2"));
emit("null_byte", $json->encode("\x00"));

# Unicode
emit("unicode_nfc", $json->encode("caf\x{e9}"));
emit("unicode_nfd", $json->encode("cafe\x{301}"));
emit("unicode_astral", $json->encode("\x{1F600}"));
emit("unicode_bmp_escape", $json->encode(" "));
emit("unicode_surrogate_pair", $json->encode("\x{1F600}"));

# Object structure - Perl hashes don't preserve order without Tie
emit("key_order_ba", '{"b":1,"a":2}');
emit("key_numeric_strings", '{"2":"b","1":"a","10":"c"}');
emit("nested_depth", $json->encode({ a => { b => { c => { d => 1 } } } }));
emit("empty_nested", $json->encode({ a => {}, b => [] }));

# MCP-specific protocol structures
emit("null_value", $json->encode({ name => "tool", arguments => undef }));
emit("empty_object", $json->encode({ name => "tool", arguments => {} }));
emit("absent_key", $json->encode({ name => "tool" }));
emit("isError_false", $json->encode({ content => [], isError => JSON::PP::false }));
emit("isError_absent", $json->encode({ content => [] }));
emit("id_integer", $json->encode({ jsonrpc => "2.0", id => 1 }));
emit("id_string", $json->encode({ jsonrpc => "2.0", id => "1" }));

# Boolean and null handling
emit("bool_false_vs_null", $json->encode({ a => JSON::PP::false, b => undef, c => 0, d => "" }));
emit("empty_string_key", $json->encode({ "" => "empty" }));
emit("array_with_nulls", $json->encode([1, undef, "three", undef, 5]));

# Deeply nested MCP-like structures
emit("tool_with_schema", $json->encode({
    name => "get_weather",
    description => "Get weather for a location",
    inputSchema => {
        type => "object",
        properties => {
            location => { type => "string", description => "City name" },
            units => { type => "string", enum => ["celsius", "fahrenheit"], default => "celsius" }
        },
        required => ["location"]
    }
}));
emit("content_array_mixed", $json->encode({
    content => [
        { type => "text", text => "Hello" },
        { type => "image", data => "base64...", mimeType => "image/png" }
    ]
}));
emit("error_response", $json->encode({
    jsonrpc => "2.0", id => 1,
    error => { code => -32602, message => "Invalid params", data => { param => "missing_field" } }
}));

# Cross-SDK Differential Test Results

**Languages tested:** javascript, python, ruby, go, swift, java, perl
**Total tests:** 40
**Agree:** 12 | **Diverge:** 28

| Test | javascript | python | ruby | go | swift | java | perl | Status |
|------|------|------|------|------|------|------|------|--------|
| float_1e20 | `100000000000000000000` | `1e+20` | `1.0e+20` | `100000000000000000000` | `1e+20` | `1.0E20` | `1e+20` | **DIVERGE** |
| float_1e-7 | `1e-7` | `1e-07` | `1.0e-07` | `1e-7` | `9.9999999999999995e-08` | `1.0E-7` | `1e-07` | **DIVERGE** |
| float_0.1+0.2 | `0.30000000000000004` | `0.30000000000000004` | `0.30000000000000004` | `0.3` | `0.30000000000000004` | `0.30000000000000004` | `0.3` | **DIVERGE** |
| float_min_positive | `5e-324` | `5e-324` | `5.0e-324` | `5e-324` | `4.9406564584124654e-324` | `4.9E-324` | `4.94065645841247e-324` | **DIVERGE** |
| float_max | `1.7976931348623157e+308` | `1.7976931348623157e+308` | `1.7976931348623157e+308` | `1.7976931348623157e+308` | `1.7976931348623157e+308` | `1.7976931348623157E308` | `1.79769313486232e+308` | **DIVERGE** |
| float_subnormal | `2.2250738585072014e-308` | `2.2250738585072014e-308` | `2.2250738585072014e-308` | `2.2250738585072014e-308` | `2.2250738585072014e-308` | `2.2250738585072014E-308` | `2.2250738585072e-308` | **DIVERGE** |
| negative_zero | `0` | `-0.0` | `-0.0` | `-0` | `-0` | `-0.0` | `0` | **DIVERGE** |
| int_2pow53_plus1 | `9007199254740992` | `9007199254740993` | `9007199254740993` | `9007199254740993` | `9007199254740993` | `9007199254740993` | `9007199254740993` | **DIVERGE** |
| int_max_safe | `9007199254740991` | `9007199254740991` | `9007199254740991` | `9007199254740991` | `9007199254740991` | `9007199254740991` | `9007199254740991` | AGREE |
| int_negative_large | `-9007199254740991` | `-9007199254740991` | `-9007199254740991` | `-9007199254740991` | `-9007199254740991` | `-9007199254740991` | `-9007199254740991` | AGREE |
| control_char_u0001 | `{"a":"\u0001"}` | `{"a":"\u0001"}` | `{"a":"\u0001"}` | `{"a":"\u0001"}` | `{"a":"\u0001"}` | `{"a":"\u0001"}` | `{"a":"\u0001"}` | AGREE |
| control_char_u001f | `{"a":"\u001f"}` | `{"a":"\u001f"}` | `{"a":"\u001f"}` | `{"a":"\u001f"}` | `{"a":"\u001f"}` | `{"a":"\u001f"}` | `{"a":"\u001f"}` | AGREE |
| slash | `"a/b"` | `"a/b"` | `"a/b"` | `"a/b"` | `"a\/b"` | `"a/b"` | `"a/b"` | **DIVERGE** |
| backslash | `"a\\b"` | `"a\\b"` | `"a\\b"` | `"a\\b"` | `"a\\b"` | `"a\\b"` | `"a\\b"` | AGREE |
| angle_brackets | `"<script>"` | `"<script>"` | `"<script>"` | `"\u003cscript\u003e"` | `"<script>"` | `"<script>"` | `"<script>"` | **DIVERGE** |
| ampersand | `"a&b"` | `"a&b"` | `"a&b"` | `"a\u0026b"` | `"a&b"` | `"a&b"` | `"a&b"` | **DIVERGE** |
| tab_newline | `"line1\t\nline2"` | `"line1\t\nline2"` | `"line1\t\nline2"` | `"line1\t\nline2"` | `"line1\t\nline2"` | `"line1\t\nline2"` | `"line1\t\nline2"` | AGREE |
| null_byte | `"\u0000"` | `"\u0000"` | `"\u0000"` | `"\u0000"` | `"\u0000"` | `"\u0000"` | `"\u0000"` | AGREE |
| unicode_nfc | `"café"` | `"caf\u00e9"` | `"café"` | `"café"` | `"café"` | `"café"` | `"café"` | **DIVERGE** |
| unicode_nfd | `"café"` | `"cafe\u0301"` | `"café"` | `"café"` | `"café"` | `"café"` | `"café"` | **DIVERGE** |
| unicode_astral | `"😀"` | `"\ud83d\ude00"` | `"😀"` | `"😀"` | `"😀"` | `"😀"` | `"😀"` | **DIVERGE** |
| unicode_bmp_escape | `" "` | `"\u00a0"` | `" "` | `" "` | `" "` | `" "` | `" "` | **DIVERGE** |
| unicode_surrogate_pair | `"😀"` | `"\ud83d\ude00"` | `"😀"` | `"😀"` | `"😀"` | `"😀"` | `"😀"` | **DIVERGE** |
| key_order_ba | `{"b":1,"a":2}` | `{"b":1,"a":2}` | `{"b":1,"a":2}` | `{"b":1,"a":2}` | `{"a":2,"b":1}` | `{"b":1,"a":2}` | `{"b":1,"a":2}` | **DIVERGE** |
| key_numeric_strings | `{"1":"a","2":"b","10":"c"}` | `{"2":"b","1":"a","10":"c"}` | `{"2":"b","1":"a","10":"c"}` | `{"2":"b","1":"a","10":"c"}` | `{"1":"a","2":"b","10":"c"}` | `{"2":"b","1":"a","10":"c"}` | `{"2":"b","1":"a","10":"c"}` | **DIVERGE** |
| nested_depth | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | `{"a":{"b":{"c":{"d":1}}}}` | AGREE |
| empty_nested | `{"a":{},"b":[]}` | `{"a":{},"b":[]}` | `{"a":{},"b":[]}` | `{"a":{},"b":[]}` | `{"a":{},"b":[]}` | `{"a":{},"b":[]}` | `{"b":[],"a":{}}` | **DIVERGE** |
| null_value | `{"name":"tool","arguments":...` | `{"name":"tool","arguments":...` | `{"name":"tool","arguments":...` | `{"name":"tool","arguments":...` | `{"arguments":null,"name":"t...` | `{"name":"tool","arguments":...` | `{"arguments":null,"name":"t...` | **DIVERGE** |
| empty_object | `{"name":"tool","arguments":{}}` | `{"name":"tool","arguments":{}}` | `{"name":"tool","arguments":{}}` | `{"name":"tool","arguments":{}}` | `{"arguments":{},"name":"tool"}` | `{"name":"tool","arguments":{}}` | `{"arguments":{},"name":"tool"}` | **DIVERGE** |
| absent_key | `{"name":"tool"}` | `{"name":"tool"}` | `{"name":"tool"}` | `{"name":"tool"}` | `{"name":"tool"}` | `{"name":"tool"}` | `{"name":"tool"}` | AGREE |
| isError_false | `{"content":[],"isError":false}` | `{"content":[],"isError":false}` | `{"content":[],"isError":false}` | `{"content":[],"isError":false}` | `{"content":[],"isError":false}` | `{"content":[],"isError":false}` | `{"isError":false,"content":[]}` | **DIVERGE** |
| isError_absent | `{"content":[]}` | `{"content":[]}` | `{"content":[]}` | `{"content":[]}` | `{"content":[]}` | `{"content":[]}` | `{"content":[]}` | AGREE |
| id_integer | `{"jsonrpc":"2.0","id":1}` | `{"jsonrpc":"2.0","id":1}` | `{"jsonrpc":"2.0","id":1}` | `{"jsonrpc":"2.0","id":1}` | `{"id":1,"jsonrpc":"2.0"}` | `{"jsonrpc":"2.0","id":1}` | `{"id":1,"jsonrpc":"2.0"}` | **DIVERGE** |
| id_string | `{"jsonrpc":"2.0","id":"1"}` | `{"jsonrpc":"2.0","id":"1"}` | `{"jsonrpc":"2.0","id":"1"}` | `{"jsonrpc":"2.0","id":"1"}` | `{"id":"1","jsonrpc":"2.0"}` | `{"jsonrpc":"2.0","id":"1"}` | `{"id":"1","jsonrpc":"2.0"}` | **DIVERGE** |
| bool_false_vs_null | `{"a":false,"b":null,"c":0,"...` | `{"a":false,"b":null,"c":0,"...` | `{"a":false,"b":null,"c":0,"...` | `{"a":false,"b":null,"c":0,"...` | `{"a":false,"b":null,"c":0,"...` | `{"a":false,"b":null,"c":0,"...` | `{"c":0,"b":null,"d":"","a":...` | **DIVERGE** |
| empty_string_key | `{"":"empty"}` | `{"":"empty"}` | `{"":"empty"}` | `{"":"empty"}` | `{"":"empty"}` | `{"":"empty"}` | `{"":"empty"}` | AGREE |
| array_with_nulls | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | `[1,null,"three",null,5]` | AGREE |
| tool_with_schema | `{"name":"get_weather","desc...` | `{"name":"get_weather","desc...` | `{"name":"get_weather","desc...` | `{"name":"get_weather","desc...` | `{"description":"Get weather...` | `{"name":"get_weather","desc...` | `{"inputSchema":{"properties...` | **DIVERGE** |
| content_array_mixed | `{"content":[{"type":"text",...` | `{"content":[{"type":"text",...` | `{"content":[{"type":"text",...` | `{"content":[{"text":"Hello"...` | `{"content":[{"text":"Hello"...` | `{"content":[{"type":"text",...` | `{"content":[{"type":"text",...` | **DIVERGE** |
| error_response | `{"jsonrpc":"2.0","id":1,"er...` | `{"jsonrpc":"2.0","id":1,"er...` | `{"jsonrpc":"2.0","id":1,"er...` | `{"jsonrpc":"2.0","id":1,"er...` | `{"error":{"code":-32602,"da...` | `{"jsonrpc":"2.0","id":1,"er...` | `{"id":1,"jsonrpc":"2.0","er...` | **DIVERGE** |

*Generated by cross-sdk-diff.sh*

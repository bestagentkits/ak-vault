package akv1

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCJSONEncodeEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"sorted_keys_bytewise", map[string]any{"b": int64(1), "a_1": true, "a": nil, "a0": "x"}, `{"a":null,"a0":"x","a_1":true,"b":1}`},
		{"nested", map[string]any{"z": []any{map[string]any{"y": []string{"q"}, "x": int64(0)}}}, `{"z":[{"x":0,"y":["q"]}]}`},
		{"empty_containers", []any{map[string]any{}, []any{}, []string{}}, `[{},[],[]]`},
		{"max_safe_integer", int64(MaxSafeInteger), `9007199254740991`},
		{"go_int", 42, `42`},
		{"short_escapes", "\"\\\b\f\n\r\t", `"\"\\\b\f\n\r\t"`},
		{"control_lowercase_hex", "\x00\x1f", `"\u0000\u001f"`},
		{"del_and_html_raw", "\x7f<>&/", "\"\x7f<>&/\""},
		{"line_separators_raw", "  ", "\"  \""},
		{"astral_raw", "\U0001F600é", "\"\U0001F600é\""},
		{"valuer", Envelope{Kid: "k", N: "n", Ct: "c"}, `{"alg":"xc20p","ct":"c","kid":"k","n":"n","v":1}`},
	}
	for _, c := range cases {
		got, err := CJSON(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestCJSONEncodeRejects(t *testing.T) {
	cases := map[string]any{
		"unsafe_integer":   int64(MaxSafeInteger + 1),
		"negative_integer": int64(-1),
		"negative_go_int":  -1,
		"float":            1.5,
		"uppercase_key":    map[string]any{"A": int64(1)},
		"dash_key":         map[string]any{"a-b": int64(1)},
		"empty_key":        map[string]any{"": int64(1)},
		"invalid_utf8":     "\xff",
		"invalid_utf8_key": map[string]any{"a\xff": int64(1)},
		"unsupported_type": struct{}{},
		"too_deep":         nest(MaxJSONDepth + 2),
	}
	for name, v := range cases {
		if _, err := CJSON(v); CodeOf(err) != CodeBadRequest {
			t.Errorf("%s: expected bad_request, got %v", name, err)
		}
	}
	if _, err := CJSON(nest(MaxJSONDepth + 1)); err != nil {
		t.Errorf("max depth: %v", err)
	}
}

// nest returns n nested arrays: nest(2) is [[]].
func nest(n int) any {
	var v any = []any{}
	for i := 1; i < n; i++ {
		v = []any{v}
	}
	return v
}

func TestParseJSONEdgeCases(t *testing.T) {
	ok := map[string]string{
		" { \"b\" : [ 1 , 2 ] , \"a\" : \"\\u00e9\\ud83d\\ude00\" } ": "{\"a\":\"é\U0001F600\",\"b\":[1,2]}",
		`"\/"`:              `"/"`,
		`9007199254740991`:  `9007199254740991`,
		`0`:                 `0`,
		`[true,false,null]`: `[true,false,null]`,
		`"\u001F"`:          `"\u001f"`,
		strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1): strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1),
	}
	for in, want := range ok {
		v, err := ParseJSON([]byte(in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got, err := CJSON(v)
		if err != nil || string(got) != want {
			t.Errorf("%q: got %s (%v) want %s", in, got, err, want)
		}
	}
	bad := []string{
		``, ` `, `01`, `-1`, `1.0`, `1e3`, `9007199254740992`, `99999999999999999999999`,
		`{"a":1,"a":2}`, `{"A":1}`, `{"":1}`, `{a:1}`, `[1,]`, `{"a":1,}`, `[1 2]`, `"a` + "\n" + `"`,
		`"\ud800"`, `"\udc00"`, `"\ud800A"`, `"\x"`, `"\u12"`, "\"\xff\"", `NaN`, `true false`, `[`, `{"a"}`,
		strings.Repeat("[", MaxJSONDepth+2) + strings.Repeat("]", MaxJSONDepth+2),
	}
	for _, in := range bad {
		if _, err := ParseJSON([]byte(in)); CodeOf(err) != CodeBadRequest {
			t.Errorf("%q: expected bad_request, got %v", in, err)
		}
	}
}

func TestCJSONParseRequiresCanonical(t *testing.T) {
	if _, err := CJSONParse([]byte(`{"a":1,"b":[true]}`)); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	for _, in := range []string{`{"b":1,"a":2}`, `{"a": 1}`, "\"\\u00e9\"", `"\/"`, `"\u001F"`, ` 1`, "1\n"} {
		if _, err := CJSONParse([]byte(in)); CodeOf(err) != CodeBadRequest {
			t.Errorf("%q: expected bad_request, got %v", in, err)
		}
	}
}

// FuzzCJSONRoundtrip checks that anything ParseJSON accepts encodes to a
// canonical form that CJSONParse accepts and that re-encodes identically.
// The seed corpus runs under plain `go test`.
func FuzzCJSONRoundtrip(f *testing.F) {
	for _, s := range []string{
		`{}`, `[]`, `null`, `0`, `9007199254740991`, `"x"`, `{"b":1,"a":[true,false,null]}`,
		`"\u0000\u001f\u007f "`, `"😀"`, `{"k":{"k":{"k":[1,2,3]}}}`, ` [ "\"\\\b\f\n\r\t" ] `,
		`{"a":1,"a":2}`, `"\ud800"`, `1.5`, "\"\xff\"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ParseJSON(data)
		if err != nil {
			if CodeOf(err) != CodeBadRequest {
				t.Fatalf("parse error has code %q", CodeOf(err))
			}
			return
		}
		enc, err := CJSON(v)
		if err != nil {
			t.Fatalf("parsed value does not encode: %v", err)
		}
		if !utf8.Valid(enc) {
			t.Fatal("encoding is not valid UTF-8")
		}
		w, err := CJSONParse(enc)
		if err != nil {
			t.Fatalf("canonical output rejected: %v (%q)", err, enc)
		}
		again, err := CJSON(w)
		if err != nil || string(again) != string(enc) {
			t.Fatalf("roundtrip mismatch: %q vs %q (%v)", again, enc, err)
		}
	})
}

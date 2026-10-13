package akv1

import (
	"sort"
	"strconv"
	"unicode/utf8"
)

// MaxSafeInteger is 2^53-1, the largest integer in the akv1 data model.
const MaxSafeInteger = 1<<53 - 1

// MaxJSONDepth bounds nesting for both the encoder and the parser.
const MaxJSONDepth = 64

// Valuer is implemented by typed wire objects (Envelope, SignedRecord, ...).
// JSONValue returns the object in the generic value model so it can be
// canonically encoded, signed or hashed.
type Valuer interface {
	JSONValue() any
}

// CJSON serializes v as canonical JSON (spec §2): sorted ASCII keys matching
// [a-z0-9_]+, no whitespace, integers in [0, 2^53-1], minimal string escaping
// with lowercase \u00xx for control characters and raw UTF-8 for everything
// else (unlike encoding/json, "<", ">", "&", U+2028 and U+2029 are not escaped).
//
// Accepted values: nil, bool, string (valid UTF-8; invalid UTF-8 is the Go
// analogue of a lone surrogate and is rejected), int, int64, []any, []string,
// map[string]any and any Valuer. Everything else is CodeBadRequest.
func CJSON(v any) ([]byte, error) {
	out, err := encodeValue(make([]byte, 0, 128), v, 0)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CJSONString is CJSON returning a string.
func CJSONString(v any) (string, error) {
	out, err := CJSON(v)
	return string(out), err
}

func encodeValue(out []byte, v any, depth int) ([]byte, error) {
	if depth > MaxJSONDepth {
		return nil, badRequest("cjson: nesting too deep")
	}
	switch x := v.(type) {
	case nil:
		return append(out, "null"...), nil
	case bool:
		if x {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case int:
		return encodeInt(out, int64(x))
	case int64:
		return encodeInt(out, x)
	case string:
		return encodeString(out, x)
	case []any:
		out = append(out, '[')
		for i, item := range x {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = encodeValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case []string:
		items := make([]any, len(x))
		for i, s := range x {
			items[i] = s
		}
		return encodeValue(out, items, depth)
	case map[string]any:
		return encodeObject(out, x, depth)
	case Valuer:
		return encodeValue(out, x.JSONValue(), depth)
	default:
		return nil, badRequest("cjson: unsupported type")
	}
}

func encodeInt(out []byte, n int64) ([]byte, error) {
	if n < 0 || n > MaxSafeInteger {
		return nil, badRequest("cjson: numbers must be integers in [0, 2^53-1]")
	}
	return strconv.AppendInt(out, n, 10), nil
}

func encodeObject(out []byte, obj map[string]any, depth int) ([]byte, error) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys) // keys are ASCII, so byte order equals UTF-16 order
	out = append(out, '{')
	for i, k := range keys {
		if !isValidKey(k) {
			return nil, badRequest("cjson: object key must match [a-z0-9_]+")
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '"')
		out = append(out, k...)
		out = append(out, '"', ':')
		var err error
		if out, err = encodeValue(out, obj[k], depth+1); err != nil {
			return nil, err
		}
	}
	return append(out, '}'), nil
}

const hexDigits = "0123456789abcdef"

func encodeString(out []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, badRequest("cjson: lone surrogate")
	}
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, '"'), nil
}

// isValidKey reports whether k matches [a-z0-9_]+.
func isValidKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

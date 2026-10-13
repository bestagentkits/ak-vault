package akv1

import (
	"unicode/utf16"
)

// Boundary validators for untrusted wire objects in the generic value model.
// Every parser goes through these so the same shape rules apply everywhere;
// failures are CodeBadRequest except version checks (CodeUnsupportedVersion).
// The order of checks in each parser mirrors the TypeScript reference so the
// first failing rule (and therefore the error code) is identical.

// IDBytes is the decoded size of opaque IDs (vault_id, item_id, conflict_id, jti).
const IDBytes = 16

const maxText = 1024

func asObject(v any, what string) (map[string]any, error) {
	if val, ok := v.(Valuer); ok {
		v = val.JSONValue()
	}
	obj, ok := v.(map[string]any)
	if !ok || obj == nil {
		return nil, badRequest("%s must be an object", what)
	}
	return obj, nil
}

// exactKeys requires every key in required and allows only keys in optional besides.
func exactKeys(obj map[string]any, required []string, what string, optional ...string) error {
	for _, k := range required {
		if _, ok := obj[k]; !ok {
			return badRequest("%s.%s is required", what, k)
		}
	}
	for k := range obj {
		if !contains(required, k) && !contains(optional, k) {
			return badRequest("%s has an unknown field", what)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// checkVersion fails closed on any "v" other than the integer 1.
func checkVersion(obj map[string]any, what string) error {
	if n, ok := toInt(obj["v"]); !ok || n != 1 {
		return newErr(CodeUnsupportedVersion, "%s: unsupported version", what)
	}
	return nil
}

// toInt accepts the integer representations of the value model.
func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}

func asInt(v any, what string, min, max int64) (int64, error) {
	n, ok := toInt(v)
	if !ok || n < min || n > max {
		return 0, badRequest("%s must be an integer in [%d, %d]", what, min, max)
	}
	return n, nil
}

func asUint(v any, what string) (int64, error) { return asInt(v, what, 0, MaxSafeInteger) }

func asBool(v any, what string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, badRequest("%s must be a boolean", what)
	}
	return b, nil
}

// utf16Len is the JavaScript `string.length` of s (UTF-16 code units), so
// length limits match the reference exactly for non-ASCII text.
func utf16Len(s string) int {
	n := 0
	for _, r := range s { // invalid UTF-8 bytes range as U+FFFD (one unit each)
		n += utf16.RuneLen(r)
	}
	return n
}

func asString(v any, what string, maxLen, minLen int) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", badRequest("%s must be a string of length %d..%d", what, minLen, maxLen)
	}
	if n := utf16Len(s); n < minLen || n > maxLen {
		return "", badRequest("%s must be a string of length %d..%d", what, minLen, maxLen)
	}
	return s, nil
}

func asEnum(v any, allowed []string, what string) (string, error) {
	s, ok := v.(string)
	if !ok || !contains(allowed, s) {
		return "", badRequest("%s has an unsupported value", what)
	}
	return s, nil
}

func asArray(v any, what string, maxLen int) ([]any, error) {
	switch x := v.(type) {
	case []any:
		if len(x) <= maxLen {
			return x, nil
		}
	case []string:
		if len(x) <= maxLen {
			out := make([]any, len(x))
			for i, s := range x {
				out[i] = s
			}
			return out, nil
		}
	}
	return nil, badRequest("%s must be an array of at most %d entries", what, maxLen)
}

// asB64 requires a base64url string decoding to exactly length bytes (any
// length when length < 0) and returns the original string.
func asB64(v any, what string, length int) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", badRequest("%s must be base64url", what)
	}
	b, err := B64Decode(s)
	if err != nil {
		return "", err
	}
	if length >= 0 && len(b) != length {
		return "", badRequest("%s must be %d bytes", what, length)
	}
	return s, nil
}

func asID(v any, what string) (string, error) { return asB64(v, what, IDBytes) }

// asIDList validates an array of unique opaque IDs.
func asIDList(v any, what string, maxLen int) ([]string, error) {
	arr, err := asArray(v, what, maxLen)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(arr))
	seen := make(map[string]bool, len(arr))
	for _, item := range arr {
		id, err := asID(item, what+"[]")
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	for _, id := range out {
		if seen[id] {
			return nil, badRequest("%s contains duplicates", what)
		}
		seen[id] = true
	}
	return out, nil
}

// ValidateID checks that s is b64 of exactly 16 bytes (an opaque protocol ID).
func ValidateID(s string) error {
	_, err := asID(s, "id")
	return err
}

func stringsToAny(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

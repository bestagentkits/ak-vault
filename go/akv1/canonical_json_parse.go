package akv1

import (
	"bytes"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseJSON parses JSON text under the restricted akv1 data model (spec §2).
//
// The result uses the generic value model: nil, bool, int64, string, []any
// and map[string]any. Unlike encoding/json it rejects, with CodeBadRequest:
// invalid UTF-8, floats, exponents, negative numbers, leading zeros, integers
// above 2^53-1, duplicate keys, keys outside [a-z0-9_]+, lone surrogates
// (escaped), unescaped control characters, nesting deeper than MaxJSONDepth
// and trailing data. It does NOT require canonical key order or whitespace;
// see CJSONParse for that.
func ParseJSON(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, badRequest("invalid UTF-8")
	}
	p := &jsonParser{text: text}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.text) {
		return nil, p.fail("trailing data")
	}
	return v, nil
}

// CJSONParse parses input that MUST already be canonical JSON (e.g. a signed
// wire blob or a decrypted payload). Any non-canonical form (whitespace, key
// order, needless escapes, uppercase hex) is CodeBadRequest.
func CJSONParse(text []byte) (any, error) {
	v, err := ParseJSON(text)
	if err != nil {
		return nil, err
	}
	canon, err := CJSON(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, text) {
		return nil, badRequest("cjson: input is not canonical")
	}
	return v, nil
}

type jsonParser struct {
	text []byte
	pos  int
}

func (p *jsonParser) fail(msg string) error {
	return badRequest("invalid JSON: %s", msg)
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.text) {
		switch p.text[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) peek() int {
	if p.pos < len(p.text) {
		return int(p.text[p.pos])
	}
	return -1
}

func (p *jsonParser) literal(lit string, v any) (any, error) {
	if !bytes.HasPrefix(p.text[p.pos:], []byte(lit)) {
		return nil, p.fail("expected " + lit)
	}
	p.pos += len(lit)
	return v, nil
}

func (p *jsonParser) value(depth int) (any, error) {
	if depth > MaxJSONDepth {
		return nil, p.fail("nesting too deep")
	}
	p.skipWS()
	switch c := p.peek(); {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.stringValue()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c >= '0' && c <= '9':
		return p.integer()
	default:
		return nil, p.fail("unexpected character")
	}
}

func (p *jsonParser) integer() (any, error) {
	var n int64
	if p.text[p.pos] == '0' {
		p.pos++
	} else {
		for p.pos < len(p.text) && p.text[p.pos] >= '0' && p.text[p.pos] <= '9' {
			if n > (MaxSafeInteger-int64(p.text[p.pos]-'0'))/10 {
				return nil, p.fail("integer exceeds 2^53-1")
			}
			n = n*10 + int64(p.text[p.pos]-'0')
			p.pos++
		}
	}
	if c := p.peek(); c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9') {
		return nil, p.fail("only non-negative integers without leading zeros, fractions or exponents are allowed")
	}
	return n, nil
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.pos+4 > len(p.text) {
		return 0, false
	}
	var r rune
	for _, c := range p.text[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	p.pos += 4
	return r, true
}

func (p *jsonParser) stringValue() (string, error) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.pos >= len(p.text) {
			return "", p.fail("unterminated string")
		}
		c := p.text[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.fail("unescaped control character")
		case c == '\\':
			if p.pos+1 >= len(p.text) {
				return "", p.fail("bad escape")
			}
			esc := p.text[p.pos+1]
			p.pos += 2
			switch esc {
			case '"', '\\', '/':
				out = append(out, esc)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.unicodeEscape()
				if err != nil {
					return "", err
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", p.fail("bad escape")
			}
		default:
			// Input is valid UTF-8 (checked up front), so raw bytes copy through.
			out = append(out, c)
			p.pos++
		}
	}
}

// unicodeEscape decodes the hex of a \u escape (the "\u" is consumed),
// combining surrogate pairs and rejecting lone surrogates.
func (p *jsonParser) unicodeEscape() (rune, error) {
	unit, ok := p.hex4()
	if !ok {
		return 0, p.fail("bad \\u escape")
	}
	switch {
	case unit >= 0xd800 && unit <= 0xdbff:
		if !bytes.HasPrefix(p.text[p.pos:], []byte(`\u`)) {
			return 0, p.fail("lone surrogate")
		}
		p.pos += 2
		low, ok := p.hex4()
		if !ok {
			return 0, p.fail("bad \\u escape")
		}
		if low < 0xdc00 || low > 0xdfff {
			return 0, p.fail("lone surrogate")
		}
		return utf16.DecodeRune(unit, low), nil
	case unit >= 0xdc00 && unit <= 0xdfff:
		return 0, p.fail("lone surrogate")
	default:
		return unit, nil
	}
}

func (p *jsonParser) array(depth int) (any, error) {
	p.pos++
	out := []any{}
	p.skipWS()
	if p.peek() == ']' {
		p.pos++
		return out, nil
	}
	for {
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWS()
		c := p.peek()
		p.pos++
		if c == ']' {
			return out, nil
		}
		if c != ',' {
			return nil, p.fail("expected , or ]")
		}
	}
}

func (p *jsonParser) object(depth int) (any, error) {
	p.pos++
	out := map[string]any{}
	p.skipWS()
	if p.peek() == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWS()
		if p.peek() != '"' {
			return nil, p.fail("expected object key")
		}
		key, err := p.stringValue()
		if err != nil {
			return nil, err
		}
		if !isValidKey(key) {
			return nil, p.fail("object key must match [a-z0-9_]+")
		}
		if _, dup := out[key]; dup {
			return nil, p.fail("duplicate object key")
		}
		p.skipWS()
		if p.peek() != ':' {
			return nil, p.fail("expected :")
		}
		p.pos++
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[key] = v
		p.skipWS()
		c := p.peek()
		p.pos++
		if c == '}' {
			return out, nil
		}
		if c != ',' {
			return nil, p.fail("expected , or }")
		}
	}
}

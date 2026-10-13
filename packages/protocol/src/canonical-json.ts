/**
 * Canonical JSON (`cjson`), restricted RFC 8785 (spec §2): sorted ASCII keys,
 * no whitespace, integers in [0, 2^53-1] only, minimal string escaping with
 * lowercase `\u00xx` for remaining control characters and raw UTF-8 otherwise.
 */
import { fail } from './errors.js';
import { utf8Decode, utf8Encode } from './bytes.js';
import { KEY_PATTERN, MAX_JSON_DEPTH, parseJson, type JsonValue } from './json-parse.js';

const SHORT_ESCAPES: Record<number, string> = { 0x22: '\\"', 0x5c: '\\\\', 0x08: '\\b', 0x0c: '\\f', 0x0a: '\\n', 0x0d: '\\r', 0x09: '\\t' };

function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const short = SHORT_ESCAPES[code];
    if (short !== undefined) {
      out += short;
    } else if (code < 0x20) {
      out += '\\u' + code.toString(16).padStart(4, '0');
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const low = s.charCodeAt(i + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) fail('bad_request', 'cjson: lone surrogate');
      out += s[i]! + s[i + 1]!;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail('bad_request', 'cjson: lone surrogate');
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function encode(value: unknown, depth: number): string {
  if (depth > MAX_JSON_DEPTH) fail('bad_request', 'cjson: nesting too deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
        fail('bad_request', 'cjson: numbers must be integers in [0, 2^53-1]');
      }
      return String(value);
    case 'string':
      return encodeString(value);
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map((v) => encode(v, depth + 1)).join(',') + ']';
      if (!isPlainObject(value)) fail('bad_request', 'cjson: unsupported object type');
      const keys = Object.keys(value).sort();
      const parts: string[] = [];
      for (const key of keys) {
        if (!KEY_PATTERN.test(key)) fail('bad_request', 'cjson: object key must match [a-z0-9_]+');
        const v = (value as Record<string, unknown>)[key];
        if (v === undefined) fail('bad_request', 'cjson: undefined value');
        parts.push(encodeString(key) + ':' + encode(v, depth + 1));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      return fail('bad_request', `cjson: unsupported type ${typeof value}`);
  }
}

/** Serialize a value to canonical JSON text. Throws `bad_request` for values outside the data model. */
export function cjson(value: unknown): string {
  return encode(value, 0);
}

/** Canonical JSON as UTF-8 bytes. */
export function cjsonBytes(value: unknown): Uint8Array {
  return utf8Encode(cjson(value));
}

/**
 * Parse input that MUST already be canonical (e.g. a signed wire blob).
 * Any non-canonical form (whitespace, key order, escapes) is `bad_request`.
 */
export function cjsonParse(input: string | Uint8Array): JsonValue {
  const text = typeof input === 'string' ? input : utf8Decode(input);
  const value = parseJson(text);
  if (cjson(value) !== text) fail('bad_request', 'cjson: input is not canonical');
  return value;
}

export { parseJson, type JsonValue, type JsonObject } from './json-parse.js';

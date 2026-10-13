/**
 * Strict JSON parser for the restricted akv1 data model (spec §2).
 *
 * Unlike `JSON.parse` it rejects, at the lexical level: floats, exponents,
 * negative numbers, integers above 2^53-1, duplicate keys, keys outside
 * `[a-z0-9_]+`, lone surrogates (escaped or raw) and excessive nesting. It does
 * NOT require canonical key order or whitespace; see `cjsonParse` for that.
 */
import { fail } from './errors.js';

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export const MAX_JSON_DEPTH = 64;
export const KEY_PATTERN = /^[a-z0-9_]+$/;

const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);
const SIMPLE_ESCAPES: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

class Parser {
  pos = 0;
  constructor(readonly text: string) {}

  error(message: string): never {
    return fail('bad_request', `invalid JSON: ${message}`);
  }

  skipWs(): void {
    while (this.pos < this.text.length && WS.has(this.text.charCodeAt(this.pos))) this.pos++;
  }

  expect(literal: string): void {
    if (this.text.startsWith(literal, this.pos)) this.pos += literal.length;
    else this.error(`expected ${literal}`);
  }

  value(depth: number): JsonValue {
    if (depth > MAX_JSON_DEPTH) this.error('nesting too deep');
    this.skipWs();
    const ch = this.text[this.pos];
    switch (ch) {
      case '{':
        return this.object(depth);
      case '[':
        return this.array(depth);
      case '"':
        return this.string();
      case 't':
        this.expect('true');
        return true;
      case 'f':
        this.expect('false');
        return false;
      case 'n':
        this.expect('null');
        return null;
      default:
        if (ch !== undefined && ch >= '0' && ch <= '9') return this.integer();
        return this.error('unexpected character');
    }
  }

  integer(): number {
    const start = this.pos;
    if (this.text[this.pos] === '0') this.pos++;
    else while (this.pos < this.text.length && this.text[this.pos]! >= '0' && this.text[this.pos]! <= '9') this.pos++;
    const next = this.text[this.pos];
    if (next === '.' || next === 'e' || next === 'E' || (next !== undefined && next >= '0' && next <= '9')) {
      this.error('only non-negative integers without leading zeros, fractions or exponents are allowed');
    }
    const n = Number(this.text.slice(start, this.pos));
    if (!Number.isSafeInteger(n)) this.error('integer exceeds 2^53-1');
    return n;
  }

  hex4(): number {
    const h = this.text.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) this.error('bad \\u escape');
    this.pos += 4;
    return parseInt(h, 16);
  }

  string(): string {
    this.pos++; // opening quote
    let out = '';
    for (;;) {
      if (this.pos >= this.text.length) this.error('unterminated string');
      const code = this.text.charCodeAt(this.pos);
      if (code === 0x22) {
        this.pos++;
        return out;
      }
      if (code < 0x20) this.error('unescaped control character');
      if (code === 0x5c) {
        const esc = this.text[this.pos + 1];
        this.pos += 2;
        if (esc === 'u') {
          const unit = this.hex4();
          if (unit >= 0xd800 && unit <= 0xdbff) {
            if (this.text.slice(this.pos, this.pos + 2) !== '\\u') this.error('lone surrogate');
            this.pos += 2;
            const low = this.hex4();
            if (low < 0xdc00 || low > 0xdfff) this.error('lone surrogate');
            out += String.fromCharCode(unit, low);
          } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            this.error('lone surrogate');
          } else {
            out += String.fromCharCode(unit);
          }
        } else if (esc !== undefined && esc in SIMPLE_ESCAPES) {
          out += SIMPLE_ESCAPES[esc];
        } else {
          this.error('bad escape');
        }
        continue;
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.text.charCodeAt(this.pos + 1);
        if (!(low >= 0xdc00 && low <= 0xdfff)) this.error('lone surrogate');
        out += this.text.slice(this.pos, this.pos + 2);
        this.pos += 2;
        continue;
      }
      if (code >= 0xdc00 && code <= 0xdfff) this.error('lone surrogate');
      out += this.text[this.pos];
      this.pos++;
    }
  }

  array(depth: number): JsonValue[] {
    this.pos++;
    const out: JsonValue[] = [];
    this.skipWs();
    if (this.text[this.pos] === ']') {
      this.pos++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth + 1));
      this.skipWs();
      const ch = this.text[this.pos++];
      if (ch === ']') return out;
      if (ch !== ',') this.error('expected , or ]');
    }
  }

  object(depth: number): JsonObject {
    this.pos++;
    const out: JsonObject = {};
    const seen = new Set<string>();
    this.skipWs();
    if (this.text[this.pos] === '}') {
      this.pos++;
      return out;
    }
    for (;;) {
      this.skipWs();
      if (this.text[this.pos] !== '"') this.error('expected object key');
      const key = this.string();
      if (!KEY_PATTERN.test(key)) this.error('object key must match [a-z0-9_]+');
      if (seen.has(key)) this.error('duplicate object key');
      seen.add(key);
      this.skipWs();
      this.expect(':');
      // defineProperty keeps keys such as "__proto__" as plain own data properties.
      Object.defineProperty(out, key, { value: this.value(depth + 1), enumerable: true, writable: true, configurable: true });
      this.skipWs();
      const ch = this.text[this.pos++];
      if (ch === '}') return out;
      if (ch !== ',') this.error('expected , or }');
    }
  }
}

/** Parse JSON text under the restricted akv1 data model. Throws `bad_request`. */
export function parseJson(text: string): JsonValue {
  if (typeof text !== 'string') fail('bad_request', 'invalid JSON: input must be a string');
  const parser = new Parser(text);
  const value = parser.value(0);
  parser.skipWs();
  if (parser.pos !== text.length) parser.error('trailing data');
  return value;
}

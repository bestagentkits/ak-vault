/** Property tests for canonical JSON, base64url and Crockford encodings. */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { AkvError, b64decode, b64encode, cjson, cjsonParse, decodeRecoveryKey, encodeRecoveryKey, parseJson, type JsonValue } from '../src/index.js';

const key = fc.stringMatching(/^[a-z0-9_]{1,8}$/);
const leaf = fc.oneof(fc.constant(null), fc.boolean(), fc.maxSafeNat(), fc.string({ unit: 'binary', maxLength: 12 }));
const { value } = fc.letrec<{ value: JsonValue }>((tie) => ({
  value: fc.oneof({ depthSize: 'small' }, leaf, fc.array(tie('value'), { maxLength: 4 }), fc.dictionary(key, tie('value'), { maxKeys: 4 })),
}));

function throwsBadRequest(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (err) {
    return err instanceof AkvError && err.code === 'bad_request';
  }
}

describe('canonical JSON properties', () => {
  it('round-trips through the canonical-only parser', () => {
    fc.assert(fc.property(value, (v) => {
      expect(cjsonParse(cjson(v))).toEqual(v);
    }));
  });
  it('is independent of input key order and whitespace', () => {
    fc.assert(fc.property(value, (v) => {
      expect(cjson(parseJson(JSON.stringify(v, null, 2)))).toBe(cjson(v));
    }));
  });
  it('sorts keys and matches JSON.stringify string escaping for well-formed strings', () => {
    fc.assert(fc.property(fc.string({ unit: 'binary' }), (s) => {
      expect(cjson(s)).toBe(JSON.stringify(s));
    }));
    fc.assert(
      fc.property(fc.dictionary(key, fc.maxSafeNat()), (o) => {
        // Byte-order sort; note JS objects enumerate integer-like keys first, cjson must not.
        const sorted = Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1));
        expect(cjson(o)).toBe('{' + sorted.map(([k, n]) => `${JSON.stringify(k)}:${n}`).join(',') + '}');
      }),
    );
  });
  it('rejects floats, negatives and unsafe integers', () => {
    const bad = fc.double().filter((d) => !(Number.isSafeInteger(d) && d >= 0 && !Object.is(d, -0)));
    fc.assert(fc.property(bad, (d) => {
      expect(throwsBadRequest(() => cjson({ n: d }))).toBe(true);
    }));
  });
  it('rejects lone surrogates anywhere in a string', () => {
    const lone = fc.integer({ min: 0xd800, max: 0xdfff }).map((c) => String.fromCharCode(c));
    fc.assert(
      fc.property(fc.string({ maxLength: 5 }), lone, fc.string({ maxLength: 5 }), (a, s, b) => {
        expect(throwsBadRequest(() => cjson(a + s + 'x' + b))).toBe(true);
        expect(throwsBadRequest(() => parseJson(JSON.stringify(a + s + 'x' + b)))).toBe(true);
      }),
    );
  });
  it('rejects keys outside [a-z0-9_]+', () => {
    const badKey = fc.string({ minLength: 1, maxLength: 6 }).filter((k) => !/^[a-z0-9_]+$/.test(k));
    fc.assert(fc.property(badKey, (k) => {
      expect(throwsBadRequest(() => cjson({ [k]: 1 }))).toBe(true);
    }));
  });
  it('rejects non-plain values', () => {
    for (const v of [undefined, 1n, new Uint8Array(1), new Date(0), () => 1, { a: undefined }]) expect(throwsBadRequest(() => cjson(v))).toBe(true);
  });
});

describe('base64url properties', () => {
  it('round-trips and agrees with Node base64url', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        const text = b64encode(bytes);
        expect(text).toBe(Buffer.from(bytes).toString('base64url'));
        expect(b64decode(text)).toEqual(bytes);
      }),
    );
  });
  it('accepts only canonical encodings', () => {
    fc.assert(
      fc.property(fc.string({ unit: fc.constantFrom(...'AQgw-_=+/ ab'.split('')), maxLength: 12 }), (text) => {
        let decoded: Uint8Array | undefined;
        try {
          decoded = b64decode(text);
        } catch (err) {
          expect((err as AkvError).code).toBe('bad_request');
          return;
        }
        expect(b64encode(decoded)).toBe(text);
      }),
    );
  });
});

describe('Crockford recovery key properties', () => {
  it('round-trips 32-byte keys in groups of 4', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (rk) => {
        const display = encodeRecoveryKey(rk);
        expect(display).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){12}[0-9A-HJKMNP-TV-Z]{4}$/);
        expect(decodeRecoveryKey(display)).toEqual(rk);
        expect(decodeRecoveryKey(display.toLowerCase().replaceAll('-', ' '))).toEqual(rk);
      }),
    );
  });
});

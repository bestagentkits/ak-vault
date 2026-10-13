/** The generator is deterministic and the committed vectors are up to date. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildAllVectors, VECTOR_FILES } from '../scripts/vectors/index.js';
import { VECTORS_DIR } from './helpers.js';

describe('vector generator', () => {
  it('produces identical output on repeated runs', () => {
    expect(buildAllVectors()).toEqual(buildAllVectors());
  });
  it('matches the committed vector files byte for byte', () => {
    const built = buildAllVectors();
    expect(Object.keys(built)).toEqual(VECTOR_FILES);
    for (const [name, text] of Object.entries(built)) expect(readFileSync(join(VECTORS_DIR, name), 'utf8'), name).toBe(text);
  });
  it('every negative vector names a stable error code', () => {
    const codes = new Set<string>();
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') {
        for (const [k, x] of Object.entries(v)) (k === 'expect_error' ? codes.add(x as string) : walk(x));
      }
    };
    for (const text of Object.values(buildAllVectors())) walk(JSON.parse(text));
    expect([...codes].sort()).toEqual(
      ['bad_request', 'conflict', 'decrypt_failed', 'forbidden', 'invalid_signature', 'rekey_required', 'rollback', 'tombstoned', 'unauthorized', 'unsupported_version'],
    );
  });
});

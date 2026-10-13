import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import { AkvError } from '../src/index.js';

export const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../../protocol/v1/vectors');

// Vector files are untyped JSON fixtures; `any` keeps per-field access readable in tests.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Vec = any;

export function loadVector(name: string): Vec {
  const v = JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8'));
  expect(v.version).toBe(1);
  expect(typeof v.description).toBe('string');
  return v;
}

/** Assert `fn` throws an AkvError with `code`. */
export function expectCode(fn: () => unknown, code: string): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown, `expected AkvError(${code})`).toBeInstanceOf(AkvError);
  expect((thrown as AkvError).code).toBe(code);
}

export function hex(h: string): Uint8Array {
  return Uint8Array.from((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
}

export function toHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** `[name, case]` tuples for `it.each`. */
export function named(list: Vec[]): [string, Vec][] {
  return list.map((c) => [c.name, c]);
}

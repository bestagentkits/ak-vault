/**
 * Boundary validators for untrusted wire objects. Every parser in this package
 * goes through these helpers so the same shape rules apply everywhere; all
 * failures are `bad_request` except version checks (`unsupported_version`).
 */
import { fail } from './errors.js';
import { b64decode } from './base64url.js';

export type Obj = Record<string, unknown>;

/** Opaque IDs (vault_id, item_id, conflict_id, jti) are b64 of exactly 16 bytes. */
export const ID_BYTES = 16;
export const MAX_TEXT = 1024;

export function asObject(value: unknown, what: string): Obj {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail('bad_request', `${what} must be an object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail('bad_request', `${what} must be a plain object`);
  return value as Obj;
}

/** Require exactly the `required` keys plus any subset of `optional`. */
export function exactKeys(obj: Obj, required: readonly string[], what: string, optional: readonly string[] = []): void {
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, key) || obj[key] === undefined) fail('bad_request', `${what}.${key} is required`);
  }
  for (const key of Object.keys(obj)) {
    if (!required.includes(key) && !optional.includes(key)) fail('bad_request', `${what} has unknown field ${key}`);
  }
}

/** Fail closed on any version other than 1. */
export function checkVersion(obj: Obj, what: string): void {
  if (obj['v'] !== 1) fail('unsupported_version', `${what}: unsupported version`);
}

export function asInt(value: unknown, what: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    fail('bad_request', `${what} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

export function asBool(value: unknown, what: string): boolean {
  if (typeof value !== 'boolean') fail('bad_request', `${what} must be a boolean`);
  return value;
}

export function asString(value: unknown, what: string, maxLength = MAX_TEXT, minLength = 0): string {
  if (typeof value !== 'string' || value.length < minLength || value.length > maxLength) {
    fail('bad_request', `${what} must be a string of length ${minLength}..${maxLength}`);
  }
  return value;
}

export function asEnum<T extends string>(value: unknown, allowed: readonly T[], what: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) fail('bad_request', `${what} has an unsupported value`);
  return value as T;
}

export function asArray(value: unknown, what: string, maxLength = 4096): unknown[] {
  if (!Array.isArray(value) || value.length > maxLength) fail('bad_request', `${what} must be an array of at most ${maxLength} entries`);
  return value;
}

/** b64 string decoding to exactly `length` bytes; returns the original string. */
export function asB64(value: unknown, what: string, length?: number): string {
  if (typeof value !== 'string') fail('bad_request', `${what} must be base64url`);
  const bytes = b64decode(value);
  if (length !== undefined && bytes.length !== length) fail('bad_request', `${what} must be ${length} bytes`);
  return value;
}

export function asId(value: unknown, what: string): string {
  return asB64(value, what, ID_BYTES);
}

/** Array of unique opaque IDs. */
export function asIdList(value: unknown, what: string, maxLength = 4096): string[] {
  const list = asArray(value, what, maxLength).map((v, i) => asId(v, `${what}[${i}]`));
  if (new Set(list).size !== list.length) fail('bad_request', `${what} contains duplicates`);
  return list;
}

/** Strict JSON body parsing and small field validators for vault requests. */
import { parseJson, utf8Decode, type JsonObject } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';

/** Parse a request body as a JSON object (protocol data model: integers only, unique `[a-z0-9_]` keys). */
export function parseBodyObject(body: Uint8Array): JsonObject {
  if (body.length === 0) throw new ApiError('bad_request');
  const value = parseJson(utf8Decode(body));
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ApiError('bad_request');
  return value;
}

/** Require exactly `required` keys plus any of `optional`. */
export function requireKeys(obj: JsonObject, required: readonly string[], optional: readonly string[] = []): void {
  for (const key of required) if (!(key in obj)) throw new ApiError('bad_request');
  for (const key of Object.keys(obj)) if (!required.includes(key) && !optional.includes(key)) throw new ApiError('bad_request');
}

export function requireArray(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value)) throw new ApiError('bad_request');
  if (value.length > max) throw new ApiError('quota_exceeded');
  return value;
}

export function requireInt(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) throw new ApiError('bad_request');
  return value;
}

/** Parse an optional non-negative integer query parameter. */
export function queryInt(query: Record<string, string>, name: string, fallback: number, max = Number.MAX_SAFE_INTEGER): number {
  const raw = query[name];
  if (raw === undefined) return fallback;
  if (!/^\d{1,16}$/.test(raw)) throw new ApiError('bad_request');
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n > max) throw new ApiError('bad_request');
  return n;
}

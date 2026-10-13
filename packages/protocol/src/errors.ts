/**
 * Typed protocol errors. Codes are the stable set from spec §10, plus
 * `decrypt_failed`, the client-side code for an AEAD authentication failure
 * (wrong key, wrong AAD, tampered ciphertext). Messages never contain secret
 * values, names, tokens or request bodies.
 */
export const AKV_ERROR_CODES = [
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'tombstoned',
  'rekey_required',
  'unsupported_version',
  'invalid_signature',
  'rollback',
  'rate_limited',
  'quota_exceeded',
  'idempotency_mismatch',
  'sync_disabled',
  'bad_request',
  'decrypt_failed',
] as const;

export type AkvErrorCode = (typeof AKV_ERROR_CODES)[number];

export class AkvError extends Error {
  readonly code: AkvErrorCode;

  constructor(code: AkvErrorCode, message: string) {
    super(message);
    this.name = 'AkvError';
    this.code = code;
  }
}

export function isAkvError(err: unknown): err is AkvError {
  return err instanceof AkvError;
}

/** Throw an {@link AkvError}; typed `never` so it narrows control flow. */
export function fail(code: AkvErrorCode, message: string): never {
  throw new AkvError(code, message);
}

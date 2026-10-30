/**
 * Stable API errors (spec §10): `{"error":{"code","message"}}`.
 *
 * Messages are fixed strings chosen by server code. Protocol-library errors are
 * mapped to a generic message per code because their text can name request
 * fields; nothing from the request (body, token, names, IDs) is ever echoed.
 */
import { isAkvError, type AkvErrorCode } from '@ak-vault/protocol';

/**
 * Protocol codes a server may return, plus the server-only `internal` (spec §10) and
 * the input-request route codes (ADR 0004): `expired` (the request lapsed or its device
 * no longer holds it), `device_offline` (the issuing device is not connected) and
 * `device_timeout` (it did not answer; the outcome is unknown).
 */
export type ApiErrorCode = Exclude<AkvErrorCode, 'decrypt_failed'> | 'internal' | 'expired' | 'device_offline' | 'device_timeout';

const DEFAULT_STATUS: Record<ApiErrorCode, number> = {
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  tombstoned: 409,
  rekey_required: 409,
  unsupported_version: 400,
  invalid_signature: 400,
  rollback: 409,
  rate_limited: 429,
  quota_exceeded: 413,
  idempotency_mismatch: 422,
  sync_disabled: 503,
  bad_request: 400,
  internal: 500,
  expired: 410,
  device_offline: 503,
  device_timeout: 504,
};

const GENERIC_MESSAGE: Record<ApiErrorCode, string> = {
  unauthorized: 'authentication failed',
  forbidden: 'not permitted',
  not_found: 'not found',
  conflict: 'conflict',
  tombstoned: 'item was deleted at a later revision',
  rekey_required: 'writes are refused until the vault is rekeyed',
  unsupported_version: 'unsupported version or algorithm',
  invalid_signature: 'signature verification failed',
  rollback: 'state is behind or forks from a witnessed checkpoint',
  rate_limited: 'too many requests',
  quota_exceeded: 'quota exceeded',
  idempotency_mismatch: 'idempotency key reused with a different request',
  sync_disabled: 'sync is disabled',
  bad_request: 'malformed request',
  internal: 'internal error',
  expired: 'request expired',
  device_offline: 'the device holding this request is offline',
  device_timeout: 'the device did not answer in time',
};

/** Extra, non-sensitive fields allowed next to code/message (e.g. a server-assigned conflict_id). */
export type ErrorExtra = Record<string, string | number | boolean>;

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly extra: ErrorExtra | undefined;
  readonly headers: Record<string, string> | undefined;

  constructor(code: ApiErrorCode, opts: { message?: string; status?: number; extra?: ErrorExtra; headers?: Record<string, string> } = {}) {
    super(opts.message ?? GENERIC_MESSAGE[code]);
    this.name = 'ApiError';
    this.code = code;
    this.status = opts.status ?? DEFAULT_STATUS[code];
    this.extra = opts.extra;
    this.headers = opts.headers;
  }
}

/** Plain, structured-clonable API result passed from the Durable Object back to the Worker. */
export interface ApiResult {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
  /** Stable error code for operational logging only (never a message). */
  code?: string;
}

export function errorResult(err: ApiError): ApiResult {
  const result: ApiResult = {
    status: err.status,
    body: { error: { code: err.code, message: err.message, ...(err.extra ?? {}) } },
    code: err.code,
  };
  if (err.headers) result.headers = err.headers;
  return result;
}

/**
 * Convert any thrown value into an ApiError. Protocol errors keep their code with
 * a generic message; anything unexpected becomes a fail-closed 500 that reveals
 * nothing (code `internal`; a retry may succeed).
 */
export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  if (isAkvError(err)) {
    const code: ApiErrorCode = err.code === 'decrypt_failed' ? 'bad_request' : err.code;
    return new ApiError(code);
  }
  return new ApiError('internal');
}

export function okResult(body: unknown, status = 200): ApiResult {
  return { status, body };
}

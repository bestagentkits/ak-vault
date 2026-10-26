/**
 * The dashboard's error type. A code is a stable reason the UI maps to fixed
 * text; nothing in an error ever carries a name, a value, a token or a server
 * message, so an error can be shown or logged without disclosing anything.
 */
export const APP_ERROR_CODES = [
  'unsupported_browser',
  'config_invalid',
  'signin_required',
  'signin_state_mismatch',
  'signin_issuer_mismatch',
  'signin_refused',
  'token_exchange_failed',
  'device_mismatch',
  'device_removed',
  'enroll_code_invalid',
  'enroll_wrong_device',
  'enroll_not_approved',
  'enroll_sas_mismatch',
  'vault_verification_failed',
  'rollback',
  'conflict',
  'rekey_required',
  'role_forbidden',
  'write_refused',
  'invalid_name',
  'value_too_large',
  'not_found',
  'item_unreadable',
  'duplicate_name',
  'history_unavailable',
  'restore_current',
  'already_exists',
  'quota_exceeded',
  'invalid_rotation',
  'rotation_value_unchanged',
  'rotation_not_ready',
  'network',
  'server',
] as const;
export type AppErrorCode = (typeof APP_ERROR_CODES)[number];

export class AppError extends Error {
  constructor(readonly code: AppErrorCode) {
    super(code);
    this.name = 'AppError';
  }
}

export function isAppError(err: unknown): err is AppError {
  return err instanceof AppError;
}

/** The code of `err` when it is an AppError, else `fallback` (never the original message). */
export function appErrorCode(err: unknown, fallback: AppErrorCode): AppErrorCode {
  return isAppError(err) ? err.code : fallback;
}

/** Fixed text for every notice and error code. Nothing here is built from server or item data. */
import type { AppErrorCode } from '../app-error.js';
import type { Notice } from '../app-controller.js';

const TEXT: Record<AppErrorCode | Notice['code'], string> = {
  unsupported_browser: 'This browser cannot keep a non-extractable Ed25519 and X25519 device key. Use a current version of Chrome, Edge, Firefox or Safari.',
  config_invalid: 'The dashboard configuration could not be verified. Reload the page; if this persists the deployment is misconfigured.',
  signin_required: 'Your sign-in ended. Sign in again to continue.',
  signin_state_mismatch: 'That sign-in response did not match a sign-in started here, so it was refused. Start the sign-in again from this page.',
  signin_issuer_mismatch: 'That sign-in response came from an unexpected server, so it was refused.',
  signin_refused: 'The sign-in did not complete. Try again.',
  token_exchange_failed: 'The vault session could not be started. Try again.',
  device_mismatch: 'This sign-in is bound to a different device key. Sign in again from this browser.',
  device_removed: 'This browser was removed from the vault.',
  enroll_code_invalid: 'That is not a valid offer code for this vault. Paste the full code the owner device printed.',
  enroll_wrong_device: 'That offer code answers a different join code. Approve the join code shown on this page.',
  enroll_not_approved: 'The owner device has not approved this browser yet. Confirm the code on the owner device, then check again.',
  enroll_sas_mismatch: 'The approval on the vault does not match the code shown here, so it was refused. Start the enrollment again.',
  vault_verification_failed: 'The vault data did not verify. Nothing was shown or changed. Try again later or check the vault from an owner device.',
  rollback: 'The server returned an older or different vault history than this browser already verified. Nothing was shown or changed.',
  conflict: 'Another device changed this item at the same time. The list was refreshed; review it and try again.',
  rekey_required: 'An owner device must rekey this vault before changes are accepted.',
  invalid_name: 'Names must not be empty, start or end with spaces, or contain "/" or control characters.',
  value_too_large: 'That value is too large or contains invalid text.',
  not_found: 'That item no longer exists.',
  item_unreadable: 'This browser does not hold the key for that item.',
  duplicate_name: 'More than one item has that name. Resolve it from the CLI first.',
  quota_exceeded: 'The vault is full.',
  write_request_gone: 'That write request is no longer open: it expired, was already used or cancelled, or does not belong to this vault. Ask the assistant to start a new one.',
  network: 'The network request failed. Check your connection and try again.',
  server: 'The server could not complete the request. Try again shortly.',
  locked: 'The dashboard is locked. Sign in to unlock it.',
  signed_out: 'You signed out.',
  saved: 'Saved. The value was encrypted in this browser and is not shown.',
  deleted: 'Deleted.',
  write_cancelled: 'Cancelled. Nothing was written.',
};

export function messageFor(code: AppErrorCode | Notice['code']): string {
  return TEXT[code];
}

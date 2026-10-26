/** Fixed text for every notice and error code. Nothing here is built from server or item data. */
import type { AppErrorCode } from '../app-error.js';
import type { Notice } from '../app-controller.js';
import type { AccessChange, CapabilityId, DeniedReason } from '../sync/membership-view.js';

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
  role_forbidden: 'Your role in this vault does not allow that change, or it changed since you last refreshed. The access view was refreshed; nothing was written.',
  invalid_name: 'Names must not be empty, start or end with spaces, or contain "/" or control characters.',
  value_too_large: 'That value is too large or contains invalid text.',
  not_found: 'That item no longer exists.',
  item_unreadable: 'This browser does not hold the key for that item.',
  duplicate_name: 'More than one item has that name. Resolve it from the CLI first.',
  quota_exceeded: 'The vault is full.',
  network: 'The network request failed. Check your connection and try again.',
  server: 'The server could not complete the request. Try again shortly.',
  locked: 'The dashboard is locked. Sign in to unlock it.',
  signed_out: 'You signed out.',
  saved: 'Saved. The value was encrypted in this browser and is not shown.',
  deleted: 'Deleted.',
};

export function messageFor(code: AppErrorCode | Notice['code']): string {
  return TEXT[code];
}


export const CAPABILITY_LABEL: Record<CapabilityId, string> = {
  view_access: 'See who can access this vault, their roles and devices',
  write_secrets: 'Set and delete secrets (values are write-only)',
  invite_member: 'Invite or add a member',
  change_role: 'Change a member’s role',
  remove_member: 'Remove a member',
  remove_device: 'Remove a device',
  rekey: 'Rotate the vault key (rekey) after a removal',
};

export const DENIED_TEXT: Record<DeniedReason, string> = {
  role: 'Your role is reader, which cannot write.',
  rekey_pending: 'Paused until an owner device rekeys the vault.',
  owner_device: 'Needs a signed event from an owner device (the ak CLI). A browser session cannot post it, by design.',
  personal_vault: 'Members can only be added to a shared vault; this is a personal vault. Needs an owner device.',
};

export function changeText(change: AccessChange): string {
  switch (change.kind) {
    case 'role_changed':
      return `Your role changed from ${change.from} to ${change.to}.`;
    case 'member_removed':
      return 'A member was removed since the last refresh.';
    case 'member_added':
      return 'A member was added since the last refresh.';
    case 'rekey_started':
      return 'A removal was recorded and the vault now needs a rekey.';
    case 'rekey_done':
      return 'The vault was rekeyed.';
  }
}

/** Fixed explanations, stated as plainly as the guarantees (REVIEW.md: honest guarantees). */
export const ACCESS_NOTES = {
  membership:
    'Access is cryptographic. A member is on this list only because an owner device signed it into the vault’s membership log, which this browser verified itself. A web sign-in or an AgentKit license seat never makes someone a vault member.',
  invites:
    'There are no pending invitations to show: protocol v1 records no invitation state on the server. A member appears here once an owner device has signed the addition.',
  ownerOps:
    'Adding or removing members, changing roles and rekeying are signed by an owner device and are not available from the dashboard. This browser can only read this list and, with the right role, write secrets.',
  rekey:
    'A removal pauses writes until an owner device rekeys the vault. The new key is wrapped only for the devices that remain.',
  noClawback:
    'Rotating the vault key does not take back anything a removed member already read. Provider keys and tokens they could see stay valid until you rotate them at the provider; items marked “needs rotation” are the ones to start with.',
  needsRotate: 'Marked by an owner device in a past rekey because a removed member could read them. The mark is part of the signed history and may remain after you rotate at the provider.',
  offline:
    'This is the last membership this browser verified. If you are offline or the server is unreachable it may be out of date; refresh to verify again.',
} as const;

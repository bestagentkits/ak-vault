/**
 * SAS enrollment of the browser as a vault device (spec §3.5, §3.8). The
 * browser prints a join code; an owner device of the same account (the CLI)
 * answers with an offer code and shows a six-digit SAS; the browser shows the
 * SAS it computes from the offer, and the owner approves only when both match.
 * The approval is the owner's signed `device_add`, which the browser checks on
 * its next sync (`vault-sync.ts`) before it trusts any wrap.
 */
import { b64encode, encodeJoinCode, parseOfferCode, randomBytes, sasCode, type DeviceRecord, type OfferCode } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { Enrollment, StoredDevice } from '../keys/device-store.js';
import { deviceIdOf, kxPubB64, signPubB64, type DeviceKeyMaterial } from '../keys/webcrypto-device-keys.js';

export const DEFAULT_DEVICE_LABEL = 'Vault dashboard (browser)';

export function newJoinNonce(): string {
  return b64encode(randomBytes(16));
}

/** The record the owner adds: a human owner device of the signed-in account. */
export function deviceRecordOf(account: string, keys: DeviceKeyMaterial): DeviceRecord {
  return { device_id: deviceIdOf(keys), sign_pub: signPubB64(keys), kx_pub: kxPubB64(keys), account, role: 'owner', kind: 'human' };
}

/** Printable-ASCII label of at most 64 bytes (the join code rule). */
export function sanitizeLabel(label: string): string {
  const ascii = label.replace(/[^\x20-\x7e]/g, '').trim().slice(0, 64);
  return ascii || DEFAULT_DEVICE_LABEL;
}

export function joinCodeFor(device: StoredDevice): string {
  return encodeJoinCode({ account: device.account, device: deviceRecordOf(device.account, device.keys), nonce_j: device.nonceJ, label: device.label });
}

export function sasInputOf(device: StoredDevice, offer: Pick<OfferCode, 'vault_id' | 'initiator' | 'nonce_i' | 'nonce_j'>) {
  return { vault_id: offer.vault_id, initiator: offer.initiator, joiner: deviceRecordOf(device.account, device.keys), nonce_i: offer.nonce_i, nonce_j: offer.nonce_j };
}

/**
 * Accept a pasted offer code for this device on this vault origin. Refused when
 * it does not parse, names another origin (`enroll_code_invalid`), or answers
 * another device or join nonce (`enroll_wrong_device`). Returns the pending
 * enrollment with the SAS to show.
 */
export function acceptOffer(code: string, device: StoredDevice, origin: string): Enrollment {
  let offer: OfferCode;
  try {
    offer = parseOfferCode(code);
  } catch {
    throw new AppError('enroll_code_invalid');
  }
  if (offer.vault_origin !== origin) throw new AppError('enroll_code_invalid');
  if (offer.joiner !== deviceIdOf(device.keys) || offer.nonce_j !== device.nonceJ) throw new AppError('enroll_wrong_device');
  return {
    origin,
    vaultId: offer.vault_id,
    initiator: offer.initiator,
    nonceI: offer.nonce_i,
    trustAnchor: offer.trust_anchor,
    offerCheckpoint: offer.checkpoint,
    sas: sasCode(sasInputOf(device, offer)),
    confirmed: false,
    witnessed: null,
  };
}

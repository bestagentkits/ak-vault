/**
 * SAS enrollment transcript (spec §3.5):
 *   transcript = cjson({ctx:"akv1/sas", vault_id, initiator, joiner: device, nonce_i, nonce_j})
 *   code       = uint32be(sha256(transcript)[0:4]) mod 10^6, shown as 6 digits
 *   device_add.body.sas = b64(sha256(transcript))
 */
import { b64encode } from './base64url.js';
import { sha256 } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { parseDevice, type DeviceRecord } from './membership-types.js';
import { asB64, asId } from './validate.js';

export interface SasInput {
  vault_id: string;
  /** Device ID of the enrolling owner device. */
  initiator: string;
  /** Full device record of the joining device. */
  joiner: DeviceRecord;
  /** b64 of 16 random bytes from each side. */
  nonce_i: string;
  nonce_j: string;
}

export function sasTranscript(input: SasInput): Uint8Array {
  return cjsonBytes({
    ctx: 'akv1/sas',
    vault_id: asId(input.vault_id, 'vault_id'),
    initiator: asId(input.initiator, 'initiator'),
    joiner: parseDevice(input.joiner, 'joiner'),
    nonce_i: asB64(input.nonce_i, 'nonce_i', 16),
    nonce_j: asB64(input.nonce_j, 'nonce_j', 16),
  });
}

/** The 6-digit code both devices display. */
export function sasCode(input: SasInput): string {
  const h = sha256(sasTranscript(input));
  const n = (((h[0] as number) << 24) >>> 0) + ((h[1] as number) << 16) + ((h[2] as number) << 8) + (h[3] as number);
  return String(n % 1_000_000).padStart(6, '0');
}

/** Value for `device_add.body.sas`. */
export function sasDigest(input: SasInput): string {
  return b64encode(sha256(sasTranscript(input)));
}

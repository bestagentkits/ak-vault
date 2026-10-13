/** Device key material: Ed25519 signing key + X25519 exchange key -> device record. */
import { b64encode } from './base64url.js';
import { randomBytes } from './bytes.js';
import type { DeviceKind, DeviceRecord, Role } from './membership-types.js';
import { deviceIdFromSignPub, kxKeyPairFromSecret, signKeyPairFromSeed } from './signing.js';

export interface DeviceKeys {
  record: DeviceRecord;
  signSecret: Uint8Array;
  kxSecret: Uint8Array;
}

export interface CreateDeviceArgs {
  account: string;
  role: Role;
  kind: DeviceKind;
  /** Inject fixed secrets (test vectors only); random otherwise. */
  signSeed?: Uint8Array;
  kxSecret?: Uint8Array;
}

export function createDeviceKeys(args: CreateDeviceArgs): DeviceKeys {
  const sign = signKeyPairFromSeed(args.signSeed ?? randomBytes(32));
  const kx = kxKeyPairFromSecret(args.kxSecret ?? randomBytes(32));
  return {
    record: {
      device_id: deviceIdFromSignPub(sign.publicKey),
      sign_pub: b64encode(sign.publicKey),
      kx_pub: b64encode(kx.publicKey),
      account: args.account,
      role: args.role,
      kind: args.kind,
    },
    signSecret: sign.secretKey,
    kxSecret: kx.secretKey,
  };
}

/** Fresh opaque ID: b64 of 16 random bytes. */
export function randomId(): string {
  return b64encode(randomBytes(16));
}

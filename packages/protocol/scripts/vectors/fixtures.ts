/**
 * Deterministic fixtures for vector generation. Every secret, nonce and ID is
 * derived from a label: `seed(label) = SHA-256(utf8("akv1-test-vector/" + label))`.
 * Nothing here is random, so regenerating vectors is byte-for-byte stable.
 */
import {
  b64decode,
  b64encode,
  createDeviceKeys,
  membershipEventHash,
  sha256,
  signKeyPairFromSeed,
  signMembershipEvent,
  utf8Encode,
  deviceIdFromSignPub,
  type DeviceKeys,
  type DeviceKind,
  type JsonObject,
  type MembershipEvent,
  type MembershipEventType,
  type Role,
} from '../../src/index.js';

export const BASE_TS = 1_767_225_600_000; // 2026-01-01T00:00:00Z

export function seed(label: string): Uint8Array {
  return sha256(utf8Encode(`akv1-test-vector/${label}`));
}
export function nonce(label: string): Uint8Array {
  return seed(`nonce/${label}`).slice(0, 24);
}
export function id(label: string): string {
  return b64encode(seed(`id/${label}`).slice(0, 16));
}
export function key32(label: string): Uint8Array {
  return seed(`key/${label}`);
}
export const b64 = b64encode;

export interface VectorDevice extends DeviceKeys {
  name: string;
}

export function device(name: string, account: string, role: Role, kind: DeviceKind = 'human'): VectorDevice {
  return { name, ...createDeviceKeys({ account, role, kind, signSeed: seed(`sign/${name}`), kxSecret: seed(`kx/${name}`) }) };
}

/** Device secrets + record as published in vector files. */
export function deviceFixture(d: VectorDevice): JsonObject {
  return { name: d.name, sign_seed: b64(d.signSecret), kx_secret: b64(d.kxSecret), record: { ...d.record } };
}

export const VAULT_SHARED = id('vault/shared');
export const VAULT_PERSONAL = id('vault/personal');

export const alicePhone = device('alice-phone', 'acct_alice', 'owner');
export const aliceLaptop = device('alice-laptop', 'acct_alice', 'owner');
export const bobLaptop = device('bob-laptop', 'acct_bob', 'editor');
export const bobCi = device('bob-ci', 'acct_bob', 'editor', 'machine');
export const carolPhone = device('carol-phone', 'acct_carol', 'reader');
export const aliceNewPhone = device('alice-new-phone', 'acct_alice', 'owner');
export const aliceTablet = device('alice-tablet', 'acct_alice', 'owner');
export const stranger = device('mallory', 'acct_mallory', 'owner');

export const recoverySign = signKeyPairFromSeed(seed('recovery-sign/alice'));
export const recoveryAuthor = deviceIdFromSignPub(recoverySign.publicKey);
export const recoverySignPub = b64(recoverySign.publicKey);
/** The owner recovery signing key after `recovery_rotate`. */
export const recoverySign2 = signKeyPairFromSeed(seed('recovery-sign/alice/rotated'));
export const recoverySignPub2 = b64(recoverySign2.publicKey);

export interface ChainStep {
  type: MembershipEventType;
  body: JsonObject;
  /** Signing secret of the author and the author ID written into the event. */
  signer: Uint8Array;
  author: string;
  /** Field overrides applied before signing (for negative vectors). */
  override?: Partial<Omit<MembershipEvent, 'sig' | 'body'>>;
}

/**
 * Build a signed chain without verifying it: seq = index, prev = hash of the
 * previous event, membership_epoch = seq, key_epoch follows rekey bodies.
 */
export function buildChain(vaultId: string, steps: ChainStep[]): MembershipEvent[] {
  const events: MembershipEvent[] = [];
  let keyEpoch = 1;
  steps.forEach((step, i) => {
    if (step.type === 'rekey') keyEpoch = step.body['new_key_epoch'] as number;
    const unsigned = {
      v: 1 as const,
      type: step.type,
      vault_id: vaultId,
      seq: i,
      prev: i === 0 ? '' : membershipEventHash(events[i - 1]!),
      membership_epoch: i,
      key_epoch: keyEpoch,
      ts: BASE_TS + i * 60_000,
      author: step.author,
      body: step.body,
      ...step.override,
    };
    events.push(signMembershipEvent(unsigned, step.signer));
  });
  return events;
}

export function by(d: VectorDevice): Pick<ChainStep, 'signer' | 'author'> {
  return { signer: d.signSecret, author: d.record.device_id };
}

export const byRecovery: Pick<ChainStep, 'signer' | 'author'> = { signer: recoverySign.secretKey, author: recoveryAuthor };
export const byRecovery2: Pick<ChainStep, 'signer' | 'author'> = { signer: recoverySign2.secretKey, author: deviceIdFromSignPub(recoverySign2.publicKey) };

/** Run `fn` and return the AkvError code it throws (or throw if it does not). */
export function expectCode(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string') return code;
    throw err;
  }
  throw new Error('expected an AkvError');
}

/** Build a negative vector after proving the implementation throws `expected`. */
export function negative(name: string, expected: string, data: Record<string, unknown>, check: () => unknown): Record<string, unknown> {
  const code = expectCode(check);
  if (code !== expected) throw new Error(`vector ${name}: expected ${expected}, implementation threw ${code}`);
  return { name, ...data, expect_error: expected };
}

/** Flip the low bit of byte `index` of a b64 value (tamper helper). */
export function flipByte(value: string, index = 0): string {
  const bytes = b64decode(value).slice();
  bytes[index] = (bytes[index] as number) ^ 1;
  return b64encode(bytes);
}

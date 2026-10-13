/**
 * Signed item records (spec §5): build, sign, structural parse, signature
 * verification against membership, and write authorization.
 */
import { sha256b64 } from './base64url.js';
import { epochTag, parseEnvelope, type Envelope } from './aead.js';
import { fail } from './errors.js';
import type { MembershipState } from './membership-types.js';
import { SIGN_CONTEXT, signObject, signingInput, verifyObject } from './signing.js';
import { asB64, asBool, asId, asIdList, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface SignedRecord {
  v: 1;
  vault_id: string;
  item_id: string;
  base_revision: number;
  key_epoch: number;
  tombstone: boolean;
  author: string;
  ts: number;
  resolves: string[];
  env: Envelope;
  sig: string;
}

export type UnsignedRecord = Omit<SignedRecord, 'v' | 'sig'>;

export const MAX_RESOLVES = 256;

export function signRecord(fields: UnsignedRecord, secretKey: Uint8Array): SignedRecord {
  return signObject(SIGN_CONTEXT.record, { v: 1 as const, ...fields }, secretKey);
}

/** `b64(sha256(record signing input))`, used for state digests and replay detection. */
export function recordDigest(record: SignedRecord): string {
  return sha256b64(signingInput(SIGN_CONTEXT.record, record));
}

/** Structural validation of an untrusted record. `env.kid` must be the epoch tag `e<key_epoch>`. */
export function parseRecord(value: unknown, what = 'record'): SignedRecord {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'item_id', 'base_revision', 'key_epoch', 'tombstone', 'author', 'ts', 'resolves', 'env', 'sig'], what);
  const record: SignedRecord = {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    item_id: asId(obj['item_id'], `${what}.item_id`),
    base_revision: asInt(obj['base_revision'], `${what}.base_revision`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    tombstone: asBool(obj['tombstone'], `${what}.tombstone`),
    author: asId(obj['author'], `${what}.author`),
    ts: asInt(obj['ts'], `${what}.ts`),
    resolves: asIdList(obj['resolves'], `${what}.resolves`, MAX_RESOLVES),
    env: parseEnvelope(obj['env'], `${what}.env`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
  if (record.env.kid !== epochTag(record.key_epoch)) fail('bad_request', `${what}.env.kid must be the epoch tag`);
  return record;
}

/** Verify a record signature against an explicit signing key (e.g. historical authors). */
export function verifyRecordSignature(value: unknown, signPub: string | Uint8Array): SignedRecord {
  const record = parseRecord(value);
  verifyObject(SIGN_CONTEXT.record, record, signPub);
  return record;
}

/**
 * Parse and verify a record against verified membership: same vault, author is
 * a current device (`forbidden` otherwise), valid signature (`invalid_signature`).
 */
export function verifyRecord(value: unknown, state: MembershipState): SignedRecord {
  const record = parseRecord(value);
  if (record.vault_id !== state.vault_id) fail('bad_request', 'record belongs to another vault');
  const device = state.devices.find((d) => d.device_id === record.author);
  if (!device) fail('forbidden', 'record author is not a current device');
  verifyObject(SIGN_CONTEXT.record, record, device.sign_pub);
  return record;
}

/**
 * Write-side authorization (server and client): author must be a human
 * `owner`/`editor` device (`forbidden`), the vault must not be in
 * `rekey_required` (`rekey_required`), and `key_epoch` must equal the current
 * key epoch (`bad_request`).
 */
export function authorizeRecordWrite(state: MembershipState, record: SignedRecord): void {
  const device = state.devices.find((d) => d.device_id === record.author);
  if (!device) fail('forbidden', 'record author is not a current device');
  if (device.kind !== 'human' || (device.role !== 'owner' && device.role !== 'editor')) fail('forbidden', 'author may not write');
  if (state.rekey_required) fail('rekey_required', 'writes are refused until rekey');
  if (record.key_epoch !== state.key_epoch) fail('bad_request', 'record key_epoch is not the current key epoch');
}

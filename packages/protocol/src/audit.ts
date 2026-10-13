/**
 * Encrypted, hash-chained audit stream (spec §7). Entry `i` is an AEAD envelope
 * with aad `{ctx:"akv1/audit", vault_id, seq:i, prev}` where `prev` is
 * `b64 sha256(cjson(entry i-1))` ('' for seq 0). Audit checkpoints are
 * `{v:1, vault_id, seq, head, author, ts, sig}` signed with `akv1/audit-checkpoint`,
 * where `head` is the hash of entry `seq`.
 */
import { sha256b64 } from './base64url.js';
import { assertUniqueNonces, openEnvelope, parseEnvelope, sealEnvelope, type Envelope } from './aead.js';
import { cjsonBytes, cjsonParse, type JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import type { MembershipState } from './membership-types.js';
import { SIGN_CONTEXT, signObject, verifyObject } from './signing.js';
import { asArray, asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface AuditHead {
  seq: number;
  head: string;
}

export interface AuditCheckpoint {
  v: 1;
  vault_id: string;
  seq: number;
  head: string;
  author: string;
  ts: number;
  sig: string;
}

export function auditAad(vaultId: string, seq: number, prev: string): JsonObject {
  return { ctx: 'akv1/audit', vault_id: vaultId, seq, prev };
}

export function auditEntryHash(entry: Envelope): string {
  return sha256b64(cjsonBytes(entry));
}

export interface AppendAuditArgs {
  key: Uint8Array;
  vaultId: string;
  kid: string;
  /** Head of the existing chain, or null for the first entry. */
  head: AuditHead | null;
  event: JsonObject;
  /** Inject a fixed nonce (test vectors only). */
  nonce?: Uint8Array;
}

export function appendAuditEntry(args: AppendAuditArgs): { entry: Envelope; head: AuditHead } {
  const seq = args.head ? args.head.seq + 1 : 0;
  const prev = args.head ? args.head.head : '';
  const opts = args.nonce ? { kid: args.kid, nonce: args.nonce } : { kid: args.kid };
  const entry = sealEnvelope(args.key, cjsonBytes(args.event), auditAad(asId(args.vaultId, 'vault_id'), seq, prev), opts);
  return { entry, head: { seq, head: auditEntryHash(entry) } };
}

export interface VerifyAuditOptions {
  key: Uint8Array;
  vaultId: string;
  /** Witnessed audit checkpoint (already signature-verified). */
  witnessed?: AuditHead;
}

/**
 * Replay and decrypt the whole chain. Reordered, dropped or substituted entries
 * fail AEAD (`decrypt_failed`); a chain shorter than, or with a different entry
 * at, the witnessed checkpoint is `rollback`; reused nonces are `bad_request`.
 */
export function verifyAuditChain(entries: readonly unknown[], opts: VerifyAuditOptions): { events: JsonObject[]; head: AuditHead | null } {
  const parsed = asArray(entries, 'audit entries', 1_000_000).map((e, i) => parseEnvelope(e, `audit entry ${i}`));
  assertUniqueNonces(parsed);
  const vaultId = asId(opts.vaultId, 'vault_id');
  const events: JsonObject[] = [];
  const hashes: string[] = [];
  parsed.forEach((entry, seq) => {
    const prev = seq === 0 ? '' : hashes[seq - 1]!;
    const plaintext = openEnvelope(opts.key, entry, auditAad(vaultId, seq, prev));
    events.push(asObject(cjsonParse(plaintext), 'audit event') as JsonObject);
    hashes.push(auditEntryHash(entry));
  });
  if (opts.witnessed) {
    if (opts.witnessed.seq >= hashes.length) fail('rollback', 'audit chain is behind the witnessed checkpoint');
    if (hashes[opts.witnessed.seq] !== opts.witnessed.head) fail('rollback', 'audit chain forks from the witnessed checkpoint');
  }
  const last = hashes.length - 1;
  return { events, head: last >= 0 ? { seq: last, head: hashes[last]! } : null };
}

export function signAuditCheckpoint(fields: Omit<AuditCheckpoint, 'v' | 'sig'>, secretKey: Uint8Array): AuditCheckpoint {
  return signObject(SIGN_CONTEXT.auditCheckpoint, { v: 1 as const, ...fields }, secretKey);
}

export function parseAuditCheckpoint(value: unknown, what = 'audit checkpoint'): AuditCheckpoint {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'seq', 'head', 'author', 'ts', 'sig'], what);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    seq: asInt(obj['seq'], `${what}.seq`),
    head: asB64(obj['head'], `${what}.head`, 32),
    author: asId(obj['author'], `${what}.author`),
    ts: asInt(obj['ts'], `${what}.ts`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

/** Verify an audit checkpoint signed by a current member device. */
export function verifyAuditCheckpoint(value: unknown, state: MembershipState): AuditCheckpoint {
  const cp = parseAuditCheckpoint(value);
  if (cp.vault_id !== state.vault_id) fail('bad_request', 'audit checkpoint belongs to another vault');
  const device = state.devices.find((d) => d.device_id === cp.author);
  if (!device) fail('forbidden', 'audit checkpoint author is not a current device');
  verifyObject(SIGN_CONTEXT.auditCheckpoint, cp, device.sign_pub);
  return cp;
}

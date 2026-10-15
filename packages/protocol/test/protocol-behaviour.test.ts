/** Behaviour not covered by fixed vectors: random paths, limits, builders and runtime neutrality. */
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  appendAuditEntry, applyRecord, buildGenesisEvent, buildProof, createDeviceKeys, decodeRecoveryKey, effectiveGrant, encodeRecoveryKey,
  generateRecoveryKey, nextMembershipEvent, openEnvelope, randomId, sealEnvelope, sealItem, signRecord, unwrapFromDevice, unwrapWithPassword,
  unwrapWithRecoveryKey, verifyAuditChain, verifyMembershipChain, verifyProof, verifyRecordSignature, wrapToDevice, wrapWithPassword,
  wrapWithRecoveryKey, b64decode, b64encode, randomBytes, utf8Encode, MAX_PLAINTEXT_BYTES, type LocalGrant,
} from '../src/index.js';
import { expectCode } from './helpers.js';

const vaultId = randomId();
const vk = new Uint8Array(32).fill(7);

describe('envelopes and wraps (random nonces / keys)', () => {
  it('uses fresh nonces and enforces the plaintext limit', () => {
    const a = sealEnvelope(vk, utf8Encode('x'), { ctx: 't' }, { kid: 'e1' });
    const b = sealEnvelope(vk, utf8Encode('x'), { ctx: 't' }, { kid: 'e1' });
    expect(a.n).not.toBe(b.n);
    expect(b64decode(a.n)).toHaveLength(24);
    expect(openEnvelope(vk, a, { ctx: 't' }, 'e1')).toEqual(utf8Encode('x'));
    expectCode(() => openEnvelope(vk, a, { ctx: 't' }, 'e2'), 'bad_request');
    expect(() => sealEnvelope(vk, new Uint8Array(MAX_PLAINTEXT_BYTES), {}, { kid: 'e1' })).not.toThrow();
    expectCode(() => sealEnvelope(vk, new Uint8Array(MAX_PLAINTEXT_BYTES + 1), {}, { kid: 'e1' }), 'bad_request');
    expectCode(() => sealEnvelope(new Uint8Array(16), new Uint8Array(1), {}, { kid: 'e1' }), 'bad_request');
  });
  it('round-trips device, password (default params) and recovery wraps', () => {
    const dev = createDeviceKeys({ account: 'a', role: 'owner', kind: 'human' });
    const wrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: dev.record });
    expect(unwrapFromDevice({ wrap, vaultId, deviceId: dev.record.device_id, kxSecret: dev.kxSecret })).toEqual(vk);
    const pw = wrapWithPassword({ vk, vaultId, keyEpoch: 2, password: 'pw' });
    expect(pw).toMatchObject({ t: 3, m: 65_536, p: 1 });
    expect(unwrapWithPassword({ wrap: pw, vaultId, password: 'pw' })).toEqual({ vk, needsUpgrade: false });
    const rk = generateRecoveryKey();
    const rw = wrapWithRecoveryKey({ vk, vaultId, keyEpoch: 1, rk });
    expect(unwrapWithRecoveryKey({ wrap: rw, vaultId, rk: decodeRecoveryKey(encodeRecoveryKey(rk)) })).toEqual(vk);
    expectCode(() => wrapWithPassword({ vk, vaultId, keyEpoch: 1, password: '' }), 'bad_request');
  });
});

describe('membership builders', () => {
  it('nextMembershipEvent produces a verifiable chain', () => {
    const owner = createDeviceKeys({ account: 'acct', role: 'owner', kind: 'human' });
    const second = createDeviceKeys({ account: 'acct', role: 'owner', kind: 'human' });
    const recovery = createDeviceKeys({ account: 'x', role: 'owner', kind: 'human' });
    const genesis = buildGenesisEvent(
      { vault_id: vaultId, ts: 1, author: owner.record.device_id, body: { vault_kind: 'personal', owner_account: 'acct', recovery_sign_pub: recovery.record.sign_pub, devices: [{ ...owner.record }], wraps_digest: b64encode(randomBytes(32)) } },
      owner.signSecret,
    );
    let state = verifyMembershipChain([genesis]);
    const add = nextMembershipEvent(state, { type: 'device_add', ts: 2, author: owner.record.device_id, body: { device: { ...second.record }, sas: b64encode(randomBytes(32)), wraps_digest: b64encode(randomBytes(32)) } }, owner.signSecret);
    state = verifyMembershipChain([genesis, add]);
    const rm = nextMembershipEvent(state, { type: 'device_remove', ts: 3, author: second.record.device_id, body: { device_id: owner.record.device_id, reason: 'retired', log_fence: 0, log_head: '' } }, second.signSecret);
    const rekey = nextMembershipEvent(verifyMembershipChain([genesis, add, rm]), { type: 'rekey', ts: 4, author: second.record.device_id, body: { new_key_epoch: 2, wraps_digest: b64encode(randomBytes(32)), needs_rotate: [] } }, second.signSecret);
    const final = verifyMembershipChain([genesis, add, rm, rekey], { vaultId });
    expect(final).toMatchObject({ seq: 3, key_epoch: 2, rekey_required: false, removed_device_ids: [owner.record.device_id] });
    expectCode(() => verifyMembershipChain([genesis], { vaultId: randomId() }), 'bad_request');
    expectCode(() => verifyMembershipChain([]), 'bad_request');
  });
});

describe('records state model', () => {
  const author = createDeviceKeys({ account: 'a', role: 'owner', kind: 'human' });
  const itemId = randomId();
  const make = (base: number) => {
    const ctx = { vault_id: vaultId, item_id: itemId, base_revision: base, key_epoch: 1, author: author.record.device_id, tombstone: false };
    const env = sealItem({ ...ctx, vk, payload: { name: 'n', value: String(base), meta: {}, sensitivity: 'normal' } });
    return signRecord({ ...ctx, ts: base, resolves: [], env }, author.signSecret);
  };
  it('assigns random conflict IDs and rejects foreign items', () => {
    const r0 = make(0);
    const s1 = applyRecord(undefined, r0).state;
    const { outcome } = applyRecord(s1, make(5));
    expect(outcome.status).toBe('conflict');
    if (outcome.status === 'conflict') expect(b64decode(outcome.conflict_id)).toHaveLength(16);
    const foreign = { ...s1, item_id: randomId() };
    expectCode(() => applyRecord(foreign, make(1)), 'bad_request');
    expect(verifyRecordSignature(r0, author.record.sign_pub)).toEqual(r0);
    expectCode(() => verifyRecordSignature(r0, createDeviceKeys({ account: 'b', role: 'owner', kind: 'human' }).record.sign_pub), 'invalid_signature');
  });

  it('an isReplay callback detects replays without an in-memory seen list', () => {
    const r0 = make(0);
    const { state } = applyRecord(undefined, r0);
    const stored = new Set(state.seen);
    const withoutSeen = { ...state, seen: [] };
    expectCode(() => applyRecord(withoutSeen, r0, { isReplay: (d) => stored.has(d) }), 'conflict');
    expect(applyRecord(withoutSeen, make(1), { isReplay: (d) => stored.has(d) }).outcome).toEqual({ status: 'applied', revision: 2 });
  });
});

describe('audit and proof edge cases', () => {
  it('empty audit chain', () => {
    const vaultKeys = (e: number) => (e === 1 ? vk : undefined);
    expect(verifyAuditChain([], { vaultKeys, vaultId, keyEpoch: 1 })).toEqual({ events: [], head: null });
    const { head } = appendAuditEntry({ vk, vaultId, keyEpoch: 1, head: null, event: { a: 1 } });
    expectCode(() => verifyAuditChain([], { vaultKeys, vaultId, keyEpoch: 1, witnessed: head }), 'rollback');
  });
  it('proof round-trip with random jti and header size limit', () => {
    const dev = createDeviceKeys({ account: 'a', role: 'owner', kind: 'human' });
    const header = buildProof({ htm: 'GET', htu: 'https://vault.agentkit.best/v1/meta', ts: 1000, token: 't', body: new Uint8Array(0), secretKey: dev.signSecret });
    const opts = { htm: 'GET', htu: 'https://vault.agentkit.best/v1/meta', token: 't', body: new Uint8Array(0), now: 1000, signPub: dev.record.sign_pub };
    expect(b64decode(verifyProof(header, opts).jti)).toHaveLength(16);
    expectCode(() => verifyProof('a'.repeat(5000), opts), 'unauthorized');
    expectCode(() => buildProof({ htm: 'get', htu: 'x', ts: 1, token: 't', body: new Uint8Array(0), secretKey: dev.signSecret }), 'bad_request');
  });
});

describe('policy', () => {
  it('does not mutate inputs', () => {
    const local: LocalGrant = { ttl_s: 10, require_approval: false, projects: ['p'], purposes: ['x'], agents: ['a'] };
    const policy = { allowed_projects: [], deny_agents: ['a'] };
    const snapshot = JSON.stringify([local, policy]);
    effectiveGrant(local, policy, 'normal');
    expect(JSON.stringify([local, policy])).toBe(snapshot);
  });
});

describe('runtime neutrality', () => {
  it('src/ has no node: imports or Node-only globals', () => {
    const dir = join(dirname(fileURLToPath(import.meta.url)), '../src');
    for (const file of readdirSync(dir)) {
      const text = readFileSync(join(dir, file), 'utf8');
      expect(text, file).not.toMatch(/from ['"]node:|require\(|\bBuffer\b|\bprocess\./);
    }
  });
});

describe('recovery bundle (random keys, default params)', () => {
  it('round-trips and enforces owner-signed checkpoints on seal', async () => {
    const { sealRecoveryBundle, openRecoveryBundle, signCheckpoint } = await import('../src/index.js');
    const owner = createDeviceKeys({ account: 'a', role: 'owner', kind: 'human' });
    const other = createDeviceKeys({ account: 'b', role: 'owner', kind: 'human' });
    const fields = { vault_id: vaultId, membership_seq: 0, membership_head: b64encode(randomBytes(32)), log_seq: 0, state_digest: b64encode(randomBytes(32)), key_epoch: 1, ts: 1 };
    const cp = signCheckpoint({ ...fields, author: owner.record.device_id }, owner.signSecret);
    const rk = generateRecoveryKey();
    const recoverySk = randomBytes(32);
    const args = { vaultId, bundleSeq: 1, vk: { '1': vk }, ownerSignPub: owner.record.sign_pub, recoverySignSk: recoverySk, checkpoint: cp, password: 'pw', rk };
    const bundle = sealRecoveryBundle(args);
    expect(bundle.pw).toMatchObject({ t: 3, m: 65_536, p: 1 });
    const opened = openRecoveryBundle({ bundle, vaultId, password: 'pw', knownBundleSeq: 1 });
    expect(opened.vk['1']).toEqual(vk);
    expect(opened.recovery_sign_sk).toEqual(recoverySk);
    expect(opened.needsUpgrade).toBe(false);
    const foreign = signCheckpoint({ ...fields, author: other.record.device_id }, other.signSecret);
    expectCode(() => sealRecoveryBundle({ ...args, checkpoint: foreign }), 'forbidden');
    expectCode(() => sealRecoveryBundle({ ...args, vk: { '2': vk } }), 'bad_request');
    expectCode(() => openRecoveryBundle({ bundle, vaultId }), 'bad_request');
  });
});

/** Signed checkpoints (anti-rollback witness) and the encrypted audit stream (spec §6, §7). */
import {
  appendAuditEntry,
  auditEntryHash,
  randomId,
  sha256b64,
  signAuditCheckpoint,
  signCheckpoint,
  verifyAuditChain,
  type AuditHead,
  type Envelope,
  type JsonObject,
} from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import type { TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

function checkpoint(fx: VaultFixture, device: TestDevice, over: Partial<{ membership_seq: number; membership_head: string; log_seq: number; state_digest: string }> = {}) {
  return signCheckpoint(
    { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(new Uint8Array(1)), key_epoch: fx.keyEpoch, ts: Date.now(), author: device.keys.record.device_id, ...over },
    device.keys.signSecret,
  );
}

describe('checkpoints', () => {
  it('stores the latest checkpoint per device and refuses rollback, forks and future state', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    await fx.write(fx.owner, randomId(), 0, { name: 'A', value: 'b' });
    const cp1 = checkpoint(fx, fx.owner, { log_seq: 1 });
    expect((await fx.post(fx.owner, '/checkpoints', cp1)).status).toBe(201);
    expect((await fx.get(laptop, '/checkpoints')).json.checkpoints).toEqual([cp1]);

    const older = await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner, { log_seq: 0 }));
    expect(older.json.error.code).toBe('rollback');
    const forked = await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner, { log_seq: 1, state_digest: sha256b64(new Uint8Array(2)) }));
    expect(forked.json.error.code).toBe('rollback');
    const badHead = await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner, { log_seq: 1, membership_head: sha256b64(new Uint8Array(3)) }));
    expect(badHead.json.error.code).toBe('rollback');
    expect((await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner, { log_seq: 99 }))).status).toBe(400);
  });

  it('refuses a checkpoint signed by a different device than the caller or with a bad signature', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.post(laptop, '/checkpoints', checkpoint(fx, fx.owner))).status).toBe(403);
    const cp = { ...checkpoint(fx, fx.owner), ts: 1 };
    expect((await fx.post(fx.owner, '/checkpoints', cp)).json.error.code).toBe('invalid_signature');
  });

  it('read-only devices (reader, machine) and read-scoped tokens cannot post checkpoints but can read them', async () => {
    const fx = await VaultFixture.create('shared');
    const machine = await fx.addDevice({ kind: 'machine' });
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    expect((await fx.post(machine, '/checkpoints', checkpoint(fx, machine))).status).toBe(403);
    expect((await fx.post(reader, '/checkpoints', checkpoint(fx, reader))).status).toBe(403);
    expect((await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner), { scope: 'vault:read' })).status).toBe(403);
    expect((await fx.post(fx.owner, '/checkpoints', checkpoint(fx, fx.owner))).status).toBe(201);
    expect((await fx.get(machine, '/checkpoints')).json.checkpoints).toHaveLength(1);
    expect((await fx.get(reader, '/checkpoints')).status).toBe(200);
  });
});

describe('audit stream', () => {
  function seal(fx: VaultFixture, head: AuditHead | null, n: number, keyEpoch = fx.keyEpoch): { entries: Envelope[]; head: AuditHead | null } {
    const entries: Envelope[] = [];
    for (let i = 0; i < n; i++) {
      const out = appendAuditEntry({ vk: fx.vk.get(keyEpoch)!, vaultId: fx.vaultId, keyEpoch, head, event: { op: 'item.read', i } });
      entries.push(out.entry);
      head = out.head;
    }
    return { entries, head };
  }
  const batch = (prevHead: AuditHead | null, entries: Envelope[]) => ({ start_seq: prevHead ? prevHead.seq + 1 : 0, prev: prevHead ? prevHead.head : '', entries: entries as unknown as JsonObject[] });

  it('appends in order, pages, and the client verifies the decrypted chain', async () => {
    const fx = await VaultFixture.create();
    const a = seal(fx, null, 3);
    expect((await fx.post(fx.owner, '/audit', batch(null, a.entries))).json.head).toEqual(a.head);
    const b = seal(fx, a.head, 2);
    expect((await fx.post(fx.owner, '/audit', batch(a.head, b.entries))).status).toBe(201);

    const p1 = await fx.get(fx.owner, '/audit?limit=3');
    expect(p1.json.has_more).toBe(true);
    const p2 = await fx.get(fx.owner, `/audit?cursor=${p1.json.next_cursor}`);
    const all = [...p1.json.entries, ...p2.json.entries].map((e: { entry: unknown }) => e.entry);
    const verified = verifyAuditChain(all, { vaultKeys: (e) => fx.vk.get(e), vaultId: fx.vaultId, keyEpoch: fx.keyEpoch });
    expect(verified.events).toHaveLength(5);
    expect(verified.head).toEqual(b.head);
  });

  it('refuses a stale head, a reused nonce, and a batch over the limit', async () => {
    const fx = await VaultFixture.create();
    const a = seal(fx, null, 2);
    await fx.post(fx.owner, '/audit', batch(null, a.entries));
    const stale = seal(fx, null, 1);
    expect((await fx.post(fx.owner, '/audit', batch(null, stale.entries))).status).toBe(409);
    const wrongPrev = { ...batch(a.head, seal(fx, a.head, 1).entries), prev: sha256b64(new Uint8Array(5)) };
    expect((await fx.post(fx.owner, '/audit', wrongPrev)).status).toBe(409);
    const reused = { ...seal(fx, a.head, 1).entries[0]!, n: a.entries[0]!.n };
    expect((await fx.post(fx.owner, '/audit', batch(a.head, [reused]))).status).toBe(400);
    expect((await fx.post(fx.owner, '/audit', batch(a.head, seal(fx, a.head, 101).entries))).json.error.code).toBe('quota_exceeded');
  });

  it('accepts audit checkpoints that match the chain and refuses forks and regressions', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const a = seal(fx, null, 2);
    const sign = (seq: number, head: string, d: TestDevice = laptop) =>
      signAuditCheckpoint({ vault_id: fx.vaultId, seq, head, author: d.keys.record.device_id, ts: Date.now() }, d.keys.signSecret);
    expect((await fx.post(laptop, '/audit', { ...batch(null, a.entries), checkpoint: sign(1, a.head!.head) })).status).toBe(201);
    const forked = await fx.post(laptop, '/audit', { ...batch(a.head, []), checkpoint: sign(1, sha256b64(new Uint8Array(7))) });
    expect(forked.json.error.code).toBe('rollback');
    const behind = await fx.post(laptop, '/audit', { ...batch(a.head, []), checkpoint: sign(0, auditEntryHash(a.entries[0]!)) });
    expect(behind.json.error.code).toBe('rollback');
    expect((await fx.get(fx.owner, '/audit')).json.checkpoints).toHaveLength(1);
    expect((await fx.post(fx.owner, '/audit', { ...batch(a.head, []), checkpoint: sign(1, a.head!.head) })).status).toBe(403);
  });

  it('refuses entries not sealed for the current key epoch, and verifies a chain across a rekey', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const a = seal(fx, null, 2);
    expect((await fx.post(fx.owner, '/audit', batch(null, a.entries))).status).toBe(201);
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fx.rekey()).status).toBe(201);
    const stale = await fx.post(fx.owner, '/audit', batch(a.head, seal(fx, a.head, 1, 1).entries));
    expect(stale.status).toBe(400);
    expect(stale.json.error.code).toBe('bad_request');
    const b = seal(fx, a.head, 2);
    expect((await fx.post(fx.owner, '/audit', batch(a.head, b.entries))).status).toBe(201);
    const all = (await fx.get(fx.owner, '/audit')).json.entries.map((e: { entry: unknown }) => e.entry);
    expect(verifyAuditChain(all, { vaultKeys: (e) => fx.vk.get(e), vaultId: fx.vaultId, keyEpoch: 2 }).events).toHaveLength(4);
    // A device holding only the new epoch still verifies the chain; older entries stay opaque.
    expect(verifyAuditChain(all, { vaultKeys: (e) => (e === 2 ? fx.vk.get(2) : undefined), vaultId: fx.vaultId, keyEpoch: 2 }).events.filter((e) => e.opaque)).toHaveLength(2);
    // Without the current epoch's key the chain is refused, never reported as all-opaque.
    expect(() => verifyAuditChain(all, { vaultKeys: (e) => (e === 1 ? fx.vk.get(1) : undefined), vaultId: fx.vaultId, keyEpoch: 2 })).toThrow(/required audit epoch/);
  });

  it('read-only devices (reader, machine) and read-scoped tokens cannot append, but can read the stream', async () => {
    const fx = await VaultFixture.create('shared');
    const machine = await fx.addDevice({ kind: 'machine' });
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const a = seal(fx, null, 1);
    for (const device of [machine, reader]) {
      const res = await fx.post(device, '/audit', batch(null, a.entries));
      expect(res.status).toBe(403);
      expect(res.json.error.code).toBe('forbidden');
    }
    expect((await fx.post(fx.owner, '/audit', batch(null, a.entries), { scope: 'vault:read' })).status).toBe(403);
    expect((await fx.post(fx.owner, '/audit', batch(null, a.entries))).status).toBe(201);
    expect((await fx.get(reader, '/audit')).json.entries).toHaveLength(1);
    expect((await fx.get(machine, '/audit')).status).toBe(200);
  });
});

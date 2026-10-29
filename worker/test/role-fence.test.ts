/**
 * Role fence: a `role_set` signs the change-log head it verified, like a removal,
 * and the Worker stores it only at the current head. Clients then refuse a record
 * whose author was not a writer at its log position, even if a colluding server
 * served it.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { b64encode, randomBytes, randomId, verifyLoggedRecord, verifyMembershipChain } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import type { MembershipStore } from '../src/vault/membership-store.js';
import { signerOf, VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'API_KEY', value: 'synthetic-value' };
const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

/** The AkvError code `fn` throws, or null when it returns. */
function codeOf(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (err) {
    return (err as { code?: string }).code ?? 'untyped';
  }
}

describe('role fence', () => {
  it('a role_set must sign the current change-log head', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fx.write(bob, randomId(), 0, v)).status).toBe(200);
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    const stale = await fx.setRole(bob.account, 'reader', 1);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('conflict');
    expect((await fx.setRole(bob.account, 'reader', 3)).json.error.code).toBe('bad_request');
    const forged = fx.buildEvent('role_set', { account: bob.account, role: 'reader', log_fence: 2, log_head: b64encode(randomBytes(32)) }, signerOf(fx.owner));
    expect((await fx.append(forged)).json.error.code).toBe('bad_request');
    const unfenced = fx.buildEvent('role_set', { account: bob.account, role: 'reader' }, signerOf(fx.owner));
    expect((await fx.append(unfenced)).json.error.code).toBe('bad_request');
    expect((await fx.setRole(bob.account, 'reader')).status).toBe(201);
    expect(fx.state.role_changes).toEqual([
      expect.objectContaining({ device_id: bob.keys.record.device_id, prev_role: 'editor', role: 'reader', log_fence: 2 }),
    ]);
  });

  it('keeps a demoted editor\'s earlier records and refuses its later ones, also when a server would serve them', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fx.write(bob, randomId(), 0, v)).status).toBe(200);
    expect((await fx.setRole(bob.account, 'reader')).status).toBe(201);

    const late = fx.record(bob, randomId(), 0, v);
    const refused = await fx.put(bob, late);
    expect(refused.status).toBe(403);
    expect(refused.json.error.code).toBe('forbidden');
    // A colluding server could place the record at position 2; the client verifier refuses it.
    expect(codeOf(() => verifyLoggedRecord(late, fx.state, 2))).toBe('forbidden');
    // The honest log, including bob's record below the fence, still verifies.
    expect(await fx.verifiedLogHeads()).toHaveLength(2);

    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    expect((await fx.setRole(bob.account, 'editor')).status).toBe(201);
    expect((await fx.write(bob, randomId(), 0, v)).status).toBe(200);
    expect(await fx.verifiedLogHeads()).toHaveLength(4);
    expect(codeOf(() => verifyLoggedRecord(late, fx.state, 2))).toBe('forbidden');
  });

  it('a stored chain holding a legacy role_set without a fence keeps accepting events', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const carol = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    // A role_set signed before role fences existed, stored as an earlier revision did.
    const legacy = fx.buildEvent('role_set', { account: bob.account, role: 'reader' }, signerOf(fx.owner));
    const next = verifyMembershipChain([...fx.events, legacy]);
    await runInDurableObject(stubFor(fx.vaultId), (instance: unknown) => {
      (instance as { membership: MembershipStore }).membership.persist(legacy, next);
    });
    fx.events.push(legacy);
    fx.state = next;
    expect(fx.state.role_changes).toEqual([expect.objectContaining({ device_id: bob.keys.record.device_id, prev_role: 'editor', role: 'reader', log_fence: null, log_head: null })]);

    const unfenced = fx.buildEvent('role_set', { account: carol.account, role: 'reader' }, signerOf(fx.owner));
    const refused = await fx.append(unfenced);
    expect(refused.status).toBe(400);
    expect(refused.json.error.code).toBe('bad_request');
    // A same-role fenced role_set bounds the legacy span from here on.
    expect((await fx.setRole(bob.account, 'reader')).status).toBe(201);
    expect(fx.state.role_changes.at(-1)).toMatchObject({ device_id: bob.keys.record.device_id, prev_role: 'reader', role: 'reader', log_fence: 1 });
    expect((await fx.removeDevice(carol)).status).toBe(201);
    expect((await fx.write(bob, randomId(), 0, v)).status).toBe(403);
    expect(await fx.verifiedLogHeads()).toHaveLength(2);
  });
});

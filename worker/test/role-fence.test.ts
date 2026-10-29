/**
 * Role fence: a `role_set` signs the change-log head it verified, like a removal,
 * and the Worker stores it only at the current head. During the transition a legacy
 * `role_set` without a fence is still accepted (VAULT_REFUSE_LEGACY_ROLE_SET). Clients then refuse a record
 * whose author was not a writer at its log position, even if a colluding server
 * served it.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { b64encode, randomBytes, randomId, verifyLoggedRecord, verifyMembershipChain, type JsonObject } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { refuseLegacyRoleSet } from '../src/env.js';
import { handleMembershipPost } from '../src/vault/membership-handlers.js';
import type { MembershipStore } from '../src/vault/membership-store.js';
import { signerOf, VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'API_KEY', value: 'synthetic-value' };
const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_DEPLOYED_REFUSE_LEGACY_ROLE_SET: string;
    }
  }
}

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

  it('accepts a legacy role_set during the transition, and refuses one after a fenced role_set', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const carol = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    // What a CLI that predates role fences sends: accepted while VAULT_REFUSE_LEGACY_ROLE_SET is "false".
    expect((await fx.append(fx.buildEvent('role_set', { account: bob.account, role: 'reader' }, signerOf(fx.owner)))).status).toBe(201);
    expect((await fx.append(fx.buildEvent('role_set', { account: carol.account, role: 'reader' }, signerOf(fx.owner)))).status).toBe(201);
    expect(fx.state.role_changes.map((c) => [c.device_id, c.prev_role, c.role, c.log_fence, c.log_head])).toEqual([
      [bob.keys.record.device_id, 'editor', 'reader', null, null],
      [carol.keys.record.device_id, 'editor', 'reader', null, null],
    ]);
    // The Worker still refuses the demoted account's writes, and the honest log verifies.
    expect((await fx.write(bob, randomId(), 0, v)).status).toBe(403);
    expect(await fx.verifiedLogHeads()).toHaveLength(2);

    // A same-role fenced role_set bounds bob's legacy span from here on.
    expect((await fx.setRole(bob.account, 'reader')).status).toBe(201);
    expect(fx.state.role_changes.at(-1)).toMatchObject({ device_id: bob.keys.record.device_id, prev_role: 'reader', role: 'reader', log_fence: 1 });
    // After a fenced role_set the chain itself refuses a legacy one, whatever the setting.
    const late = fx.buildEvent('role_set', { account: carol.account, role: 'editor' }, signerOf(fx.owner));
    expect(() => verifyMembershipChain([...fx.events, late])).toThrow(/after a fenced role_set/);
    expect((await fx.append(late)).json.error.code).toBe('bad_request');
    expect((await fx.removeDevice(carol)).status).toBe(201);
  });

  it('refuses a new legacy role_set once VAULT_REFUSE_LEGACY_ROLE_SET is on', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const legacy = fx.buildEvent('role_set', { account: bob.account, role: 'reader' }, signerOf(fx.owner));
    const seq = fx.state.seq;
    await runInDurableObject(stubFor(fx.vaultId), (instance: unknown) => {
      // The pool binds "false" to keep the transition path tested and its bindings are fixed per run, so
      // this calls the handler as the deployed Durable Object does; the parse and deployed values are tested below.
      const { sql, membership } = instance as { sql: SqlStorage; membership: MembershipStore };
      const post = () => handleMembershipPost(sql, membership, fx.vaultId, { event: legacy as unknown as JsonObject }, membership.verifyAppend(legacy), { refuseLegacyRoleSet: true });
      expect(post).toThrow(expect.objectContaining({ code: 'bad_request' }));
      expect(membership.requireState().seq).toBe(seq);
    });
    // A fenced role_set is unaffected by the setting.
    expect((await fx.setRole(bob.account, 'reader')).status).toBe(201);
  });

  it('reads the setting fail closed, and every deployed environment refuses a legacy role_set', () => {
    expect(refuseLegacyRoleSet({ VAULT_REFUSE_LEGACY_ROLE_SET: 'false' })).toBe(false);
    for (const value of ['true', 'TRUE', 'False', '', ' false', '0', undefined]) {
      expect(refuseLegacyRoleSet({ VAULT_REFUSE_LEGACY_ROLE_SET: value })).toBe(true);
    }
    expect(JSON.parse(env.TEST_DEPLOYED_REFUSE_LEGACY_ROLE_SET)).toEqual({ production: 'true', staging: 'true' });
  });
});

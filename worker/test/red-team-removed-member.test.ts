/**
 * Red-team: a member removed from a shared vault tries to reach material
 * created after the removal, from its old device and from a fresh device of
 * the same account. The remaining members get a rekey that carries no wrap for
 * the removed member and marks the exposed items `needs_rotate`.
 */
import { randomId, verifyMembershipChain, verifyRekeyWraps, type JsonObject, type MembershipEvent } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { createDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

describe('red team: removed member', () => {
  it('cannot read anything after member_remove, gets no wrap of the new epoch, and exposed items are needs-rotate', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const exposed = randomId();
    expect((await fx.write(bob, exposed, 0, { name: 'SHARED_SYNTHETIC', value: 'seen-by-bob' })).status).toBe(200);

    const head = await fx.logHead();
    const removal = fx.buildEvent('member_remove', { account: bob.account, log_fence: head });
    expect((await fx.append(removal)).status).toBe(201);

    const { event, wraps, vk } = fx.rekeyEvent();
    const rekey = fx.buildEvent('rekey', { ...(event.body as JsonObject), needs_rotate: [exposed] });
    expect((await fx.append(rekey, wraps)).status).toBe(201);
    fx.vk.set(fx.keyEpoch, vk);

    // New material at the new epoch, plus the rotated exposed item.
    const fresh = randomId();
    expect((await fx.write(fx.owner, fresh, 0, { name: 'NEW_SYNTHETIC', value: 'after-removal' })).status).toBe(200);
    expect((await fx.write(fx.owner, exposed, 1, { name: 'SHARED_SYNTHETIC', value: 'rotated' })).status).toBe(200);

    // Old device: every read and write is refused.
    for (const sub of ['/membership', '/wraps', `/wraps?membership_seq=${fx.state.seq}`, '/changes', '/checkpoints', '/audit', `/items/${fresh}`, `/items/${exposed}`]) {
      expect((await fx.get(bob, sub)).status, sub).toBe(403);
    }
    expect((await fx.write(bob, randomId(), 0, { name: 'X', value: 'y' })).status).toBe(403);

    // A fresh device of the removed account, with a valid token and proof, is not a member either.
    const bobNew = createDevice(bob.account, 'editor');
    for (const sub of ['/membership', '/wraps', '/changes', `/items/${fresh}`, '/recovery']) {
      expect((await fx.get(bobNew, sub)).status, sub).toBe(403);
    }

    // Remaining members see a verifiable chain whose rekey set excludes bob and lists the exposed item.
    const events = (await fx.get(fx.owner, '/membership')).json.events as MembershipEvent[];
    const state = verifyMembershipChain(events);
    expect(state.needs_rotate).toEqual([exposed]);
    expect(state.members.map((m) => m.account)).not.toContain(bob.account);
    const set = await fx.get(fx.owner, `/wraps?membership_seq=${state.seq}`);
    const recipients = (set.json.wraps as { rcpt: string }[]).map((w) => w.rcpt);
    expect(recipients).toEqual([fx.owner.keys.record.device_id]);
    expect(verifyRekeyWraps(events[state.seq], set.json.wraps, { state: verifyMembershipChain(events.slice(0, state.seq + 1)) })).toHaveLength(1);
  });

  it('writes by the remaining members wait for the rekey after a removal', async () => {
    const fx = await VaultFixture.create('shared');
    const bob = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fx.append(fx.buildEvent('member_remove', { account: bob.account, log_fence: await fx.logHead() }))).status).toBe(201);
    const blocked = await fx.write(fx.owner, randomId(), 0, { name: 'A', value: 'b' });
    expect([blocked.status, blocked.json.error.code]).toEqual([409, 'rekey_required']);
  });
});

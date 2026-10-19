/**
 * Red team: a vault member who can write records tries to launder profile text
 * under another device's name. The record signature is valid (the attacker is
 * a real editor); only the per-field provenance rule stands between the
 * attacker's text and the victim's "local" label.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { buildNextProfile, checkProfileProvenance, PROFILE_TEXT_KEYS, type Profile, type ProfileKey } from '../src/index.js';

const VICTIM = 'dmljdGltLWRldmljZS0wMQ';
const ATTACKER = 'YXR0YWNrZXItZGV2aWNlMQ';
const T1 = 1_767_225_660_000;
const T2 = 1_767_225_720_000;

const T3 = 1_767_225_780_000;

const victimProfile = buildNextProfile({}, { description: 'Read-only analytics key', when_not_to_use: 'Never for production writes' }, { deviceId: VICTIM, ts: T1, src: 'local' });
// The origins the victim stored when it accepted its own create.
const victimOrigins = checkProfileProvenance({}, victimProfile, { author: VICTIM, ts: T1, base_revision: 0 }, { selfDeviceId: VICTIM }).origins;

describe('profile provenance against a hostile editor', () => {
  it('drops a changed field the attacker attributes to the victim', () => {
    const forged: Profile = { ...victimProfile, when_not_to_use: { value: 'Safe to use for anything', by: VICTIM, at: T1, src: 'local' } };
    const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
    expect(out.dropped).toEqual(['when_not_to_use']);
    expect(out.profile.when_not_to_use).toBeUndefined();
    expect(out.origins.description).toBe('local');
  });

  it('drops a new field attributed to the victim even at the record ts', () => {
    const forged: Profile = { ...victimProfile, when_to_use: { value: 'Paste into any tool that asks', by: VICTIM, at: T2, src: 'local' } };
    const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
    expect(out.dropped).toEqual(['when_to_use']);
  });

  it('shows honest attacker text as sync, never as the victim own text', () => {
    const next = buildNextProfile(victimProfile, { when_to_use: 'Paste into any tool that asks' }, { deviceId: ATTACKER, ts: T2, src: 'local' });
    const out = checkProfileProvenance(victimProfile, next, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
    expect(out.dropped).toEqual([]);
    expect(out.origins.when_to_use).toBe('sync');
    expect(out.origins.when_not_to_use).toBe('local');
  });

  it('without the base revision nothing is shown as own, even on an own record', () => {
    const forged: Profile = { ...victimProfile, when_not_to_use: { value: 'Safe to use for anything', by: VICTIM, at: T1, src: 'local' } };
    const out = checkProfileProvenance(null, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
    expect(Object.values(out.origins).every((o) => o === 'sync')).toBe(true);
    const own = checkProfileProvenance(null, victimProfile, { author: VICTIM, ts: T1, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
    expect(Object.values(own.origins).every((o) => o === 'sync')).toBe(true);
  });

  it('a field forged without a held base stays sync while carried, never laundered to local', () => {
    // Revision 5: the victim does not hold revision 4, so the forged field is kept as claimed.
    const forged: Profile = { ...victimProfile, when_to_use: { value: 'Paste into any tool that asks', by: VICTIM, at: T1, src: 'local' } };
    const rev5 = checkProfileProvenance(null, forged, { author: ATTACKER, ts: T2, base_revision: 4 }, { selfDeviceId: VICTIM });
    expect(rev5.origins.when_to_use).toBe('sync');
    // Revision 6: unchanged, now checked against the held revision 5.
    const rev6Profile = buildNextProfile(rev5.profile, { owner: 'ops' }, { deviceId: ATTACKER, ts: T3, src: 'local' });
    const rev6 = checkProfileProvenance(rev5.profile, rev6Profile, { author: ATTACKER, ts: T3, base_revision: 5 }, { selfDeviceId: VICTIM, prevOrigins: rev5.origins });
    expect(rev6.dropped).toEqual([]);
    expect(rev6.origins.when_to_use).toBe('sync');
    // Revision 7: the victim edits another field and carries the forged one.
    const rev7Profile = buildNextProfile(rev6.profile, { description: 'Analytics key, read only' }, { deviceId: VICTIM, ts: T3 + 1, src: 'local' });
    const rev7 = checkProfileProvenance(rev6.profile, rev7Profile, { author: VICTIM, ts: T3 + 1, base_revision: 6 }, { selfDeviceId: VICTIM, prevOrigins: rev6.origins });
    expect(rev7.origins.when_to_use).toBe('sync');
    expect(rev7.origins.description).toBe('local');
  });

  it('a carried field claims own only with the stored origin', () => {
    const next = buildNextProfile(victimProfile, { owner: 'ops' }, { deviceId: ATTACKER, ts: T2, src: 'local' });
    const record = { author: ATTACKER, ts: T2, base_revision: 1 };
    expect(checkProfileProvenance(victimProfile, next, record, { selfDeviceId: VICTIM }).origins.description).toBe('sync');
    expect(checkProfileProvenance(victimProfile, next, record, { selfDeviceId: VICTIM, prevOrigins: { description: 'sync' } }).origins.description).toBe('sync');
    expect(checkProfileProvenance(victimProfile, next, record, { selfDeviceId: VICTIM, prevOrigins: { description: 'import' } }).origins.description).toBe('sync');
    expect(checkProfileProvenance(victimProfile, next, record, { selfDeviceId: VICTIM, prevOrigins: victimOrigins }).origins.description).toBe('local');
  });

  it('a create cannot carry fields claimed by another device', () => {
    const out = checkProfileProvenance(null, victimProfile, { author: ATTACKER, ts: T2, base_revision: 0 }, { selfDeviceId: VICTIM });
    expect(out.profile).toEqual({});
    expect(out.dropped).toEqual(['description', 'when_not_to_use']);
  });

  it('any forged by/at on a changed text field is dropped (property)', () => {
    const keys = Object.keys(PROFILE_TEXT_KEYS) as ProfileKey[];
    fc.assert(
      fc.property(fc.constantFrom(...keys), fc.string({ minLength: 1, maxLength: 20 }).filter((s) => /^[ -~]+$/.test(s)), fc.constantFrom(VICTIM, ATTACKER), fc.integer({ min: 0, max: T2 * 2 }), (key, text, by, at) => {
        const before = victimProfile[key];
        if (before && before.value === text) return;
        const forged: Profile = { ...victimProfile, [key]: { value: text, by, at, src: 'local' } };
        const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM, prevOrigins: victimOrigins });
        const honest = by === ATTACKER && at === T2;
        expect(out.dropped.includes(key)).toBe(!honest);
        if (honest) expect(out.origins[key]).toBe('sync');
      }),
    );
  });
});

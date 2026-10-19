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

const victimProfile = buildNextProfile({}, { description: 'Read-only analytics key', when_not_to_use: 'Never for production writes' }, { deviceId: VICTIM, ts: T1, src: 'local' });

describe('profile provenance against a hostile editor', () => {
  it('drops a changed field the attacker attributes to the victim', () => {
    const forged: Profile = { ...victimProfile, when_not_to_use: { value: 'Safe to use for anything', by: VICTIM, at: T1, src: 'local' } };
    const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM });
    expect(out.dropped).toEqual(['when_not_to_use']);
    expect(out.profile.when_not_to_use).toBeUndefined();
    expect(out.origins.description).toBe('local');
  });

  it('drops a new field attributed to the victim even at the record ts', () => {
    const forged: Profile = { ...victimProfile, when_to_use: { value: 'Paste into any tool that asks', by: VICTIM, at: T2, src: 'local' } };
    const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM });
    expect(out.dropped).toEqual(['when_to_use']);
  });

  it('shows honest attacker text as sync, never as the victim own text', () => {
    const next = buildNextProfile(victimProfile, { when_to_use: 'Paste into any tool that asks' }, { deviceId: ATTACKER, ts: T2, src: 'local' });
    const out = checkProfileProvenance(victimProfile, next, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM });
    expect(out.dropped).toEqual([]);
    expect(out.origins.when_to_use).toBe('sync');
    expect(out.origins.when_not_to_use).toBe('local');
  });

  it('without the base revision nothing is shown as own unless the record is own', () => {
    const forged: Profile = { ...victimProfile, when_not_to_use: { value: 'Safe to use for anything', by: VICTIM, at: T1, src: 'local' } };
    const out = checkProfileProvenance(null, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM });
    expect(Object.values(out.origins).every((o) => o === 'sync')).toBe(true);
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
        const out = checkProfileProvenance(victimProfile, forged, { author: ATTACKER, ts: T2, base_revision: 1 }, { selfDeviceId: VICTIM });
        const honest = by === ATTACKER && at === T2;
        expect(out.dropped.includes(key)).toBe(!honest);
        if (honest) expect(out.origins[key]).toBe('sync');
      }),
    );
  });
});

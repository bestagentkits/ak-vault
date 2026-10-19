/** profile.json */
import { buildNextProfile, carryForwardMeta, checkProfileProvenance, validateProfile, type Profile, type ProfileRecordContext } from '../../src/index.js';
import { alicePhone, BASE_TS, bobLaptop, carolPhone, negative } from './fixtures.js';

const ALICE = alicePhone.record.device_id;
const BOB = bobLaptop.record.device_id;
const CAROL = carolPhone.record.device_id;
const T1 = BASE_TS + 60_000;
const T2 = BASE_TS + 120_000;

export function profileVectors(): Record<string, unknown> {
  // Revision 1, written by alice; revision 2 is checked against it.
  const prev = buildNextProfile({}, { provider: 'stripe', tags: ['billing', 'live'], kind: 'api_key', description: 'Live Stripe key for checkout' }, { deviceId: ALICE, ts: T1, src: 'local' });
  const rec = (author: string, ts: number, base: number): ProfileRecordContext => ({ author, ts, base_revision: base });
  const bobEdit = buildNextProfile(prev, { environment: 'production', tags: ['billing', 'live', 'eu'] }, { deviceId: BOB, ts: T2, src: 'import' });

  type Case = { name: string; prev: Profile | null; next: unknown; record: ProfileRecordContext; self_device_id?: string };
  const run = (c: Case) => {
    const out = checkProfileProvenance(c.prev, c.next, c.record, c.self_device_id === undefined ? {} : { selfDeviceId: c.self_device_id });
    return { ...c, expect: { profile: out.profile, dropped: out.dropped, origins: out.origins } };
  };
  const field = (value: string | string[], by: string, at: number, src: 'local' | 'import' = 'local') => ({ value, by, at, src });

  const cases = [
    run({ name: 'honest_edit_keeps_every_field', prev, next: bobEdit, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'own_fields_shown_with_src', prev, next: bobEdit, record: rec(BOB, T2, 1), self_device_id: BOB }),
    run({ name: 'changed_field_by_not_author_dropped', prev, next: { ...prev, provider: field('paypal', ALICE, T2) }, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'changed_field_at_not_record_ts_dropped', prev, next: { ...prev, provider: field('paypal', BOB, T1) }, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'unchanged_field_relabelled_dropped', prev, next: { ...prev, description: { ...prev.description!, by: CAROL } }, record: rec(BOB, T2, 1), self_device_id: CAROL }),
    run({ name: 'unchanged_field_src_changed_dropped', prev, next: { ...prev, kind: { ...prev.kind!, src: 'import' } }, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'new_field_attributed_to_victim_dropped', prev, next: { ...prev, when_to_use: field('Use for every deploy', ALICE, T2) }, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'removed_field_is_fine', prev, next: { provider: prev.provider }, record: rec(BOB, T2, 1), self_device_id: ALICE }),
    run({ name: 'prev_unknown_keeps_all_shown_sync', prev: null, next: { ...prev, provider: field('paypal', ALICE, T2) }, record: rec(BOB, T2, 4), self_device_id: ALICE }),
    run({ name: 'prev_unknown_own_record_shown_src', prev: null, next: prev, record: rec(ALICE, T1, 4), self_device_id: ALICE }),
    run({ name: 'create_requires_author_fields', prev: null, next: { ...prev, environment: field('staging', BOB, T2) }, record: rec(BOB, T2, 0), self_device_id: ALICE }),
    run({ name: 'create_by_author_kept', prev: {}, next: buildNextProfile({}, { provider: 'github' }, { deviceId: BOB, ts: T2, src: 'import' }), record: rec(BOB, T2, 0) }),
    run({ name: 'tombstone_base_is_empty_profile', prev: {}, next: prev, record: rec(BOB, T2, 3), self_device_id: ALICE }),
  ];

  const bad = (name: string, profile: unknown) => negative(name, 'bad_request', { profile }, () => validateProfile(profile));
  const f = (value: unknown) => ({ value, by: ALICE, at: T1, src: 'local' });
  const meta = { description: 'legacy', whenToUse: 'legacy', 'usage.hosts': ['a'], When_Not_To_Use: 'x', 'rotate-url': 'y', kind: 'secret', item_ids: [], policy: {}, profile: {}, color: 'blue', team: 'payments' };
  return {
    version: 1,
    description:
      'Item profile and provenance (spec §5.1). validateProfile(profile) refuses an unknown key, a field object other than exactly {value, by, at, src}, a wrong type, an unknown src (local, import), kind or sensitivity, and a broken text rule (1..limit code points; no U+0000-001F, U+007F-009F, U+202A-202E, U+2066-2069, U+2028, U+2029) or list rule (1..32 items of 1..64 code points, no comma, no duplicate) with bad_request. ' +
      'checkProfileProvenance(prev, next, record, {self_device_id?}): prev is the validated profile at record.base_revision ({} for a create or a tombstone base), or null when not held (a create is always checked against {}). For each field of next: prev holds the key with an equal value (cjson of value) -> the field MUST be byte-identical to prev (same by, at, src); otherwise by MUST equal record.author and at MUST equal record.ts. A breaking field is dropped (dropped, key order); with prev null every field is kept. origins: a kept field shows its src only when by = self_device_id and (prev was held or record.author = self_device_id); otherwise "sync". cases MUST yield expect exactly. ' +
      'carry_forward: carryForwardMeta(meta) drops kind, item_ids, policy, profile and any key that, lowercased with "_", "-" and "." removed, equals a profile key with "_" removed; it MUST yield expect.',
    cases,
    invalid: [
      bad('unknown_key', { colour: f('blue') }),
      bad('field_extra_key', { provider: { ...f('stripe'), note: 'x' } }),
      bad('field_missing_src', { provider: { value: 'stripe', by: ALICE, at: T1 } }),
      bad('unknown_src', { provider: { ...f('stripe'), src: 'sync' } }),
      bad('over_length_text', { provider: f('p'.repeat(129)) }),
      bad('empty_text', { provider: f('') }),
      bad('bidi_override', { description: f('safe\u202etxt.exe') }),
      bad('line_separator', { description: f('a\u2028b') }),
      bad('control_character', { description: f('a\u0007b') }),
      bad('list_duplicate', { tags: f(['live', 'live']) }),
      bad('list_comma', { tags: f(['live,eu']) }),
      bad('list_empty', { tags: f([]) }),
      bad('list_too_many', { tags: f(Array.from({ length: 33 }, (_, i) => `t${i}`)) }),
      bad('list_item_too_long', { tags: f(['t'.repeat(65)]) }),
      bad('unknown_kind', { kind: f('ssh_key') }),
      bad('unknown_sensitivity', { sensitivity: f('secret') }),
      bad('bad_expires_at', { expires_at: f('2026-02-30T00:00:00Z') }),
      bad('rotate_url_not_https', { rotate_url: f('http://example.com/rotate') }),
      bad('text_value_is_list', { provider: f(['stripe']) }),
    ],
    valid_limits: validateProfile({ provider: f('p'.repeat(128)), description: f('😀'.repeat(1024)), tags: f(Array.from({ length: 32 }, (_, i) => `t${i}`)), expires_at: f('2028-02-29T23:59:59Z') }),
    carry_forward: { meta, expect: carryForwardMeta(meta) },
  };
}

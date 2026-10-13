/** device-add-wraps.json: the signed wrap sets delivered with genesis, device_add and member_add. */
import { verifyDeviceWraps, wrapsDigest, wrapToDevice, type JsonObject, type MembershipEvent, type X25519Wrap } from '../../src/index.js';
import { aliceNewPhone, alicePhone, aliceTablet, b64, bobCi, buildChain, by, key32, negative, nonce, seed, stranger, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';
import { ADD_SETS, PERSONAL_RECOVERY, personalChain, sharedChain, wrapsFor } from './membership.js';

/** An owner device_add at key epoch 2 whose signed set delivers only the current epoch. */
const TABLET_CURRENT_ONLY = wrapsFor([aliceTablet], 2, 'add/current-only/tablet', VAULT_PERSONAL);
const currentOnlyChain = buildChain(VAULT_PERSONAL, [
  ...PERSONAL_RECOVERY.slice(0, 4),
  { type: 'device_add', ...by(aliceNewPhone), body: { device: { ...aliceTablet.record } as unknown as JsonObject, sas: b64(seed('current-only/sas')), wraps_digest: wrapsDigest(TABLET_CURRENT_ONLY) } },
]);

const CHAINS: Record<string, MembershipEvent[]> = { shared: sharedChain, personal: personalChain, personal_current_only: currentOnlyChain };

function vaultKeys(vaultId: string, epochs: number): Record<string, string> {
  const out: Record<string, string> = {};
  for (let e = 1; e <= epochs; e++) out[String(e)] = b64(vaultId === VAULT_SHARED ? key32(`vk/epoch${e}`) : key32(`vk/${vaultId}/epoch${e}`));
  return out;
}

export function deviceAddWrapsVectors(): Record<string, unknown> {
  const set = (key: string) => ADD_SETS[key]!;
  const event = (chain: string, seq: number) => CHAINS[chain]![seq]!;
  const ok = (name: string, chain: string, seq: number, wraps: X25519Wrap[]) => {
    verifyDeviceWraps(event(chain, seq), wraps);
    return { name, chain, event_seq: seq, wraps };
  };
  const bad = (name: string, code: string, chain: string, seq: number, wraps: unknown[]) =>
    negative(name, code, { chain, event_seq: seq, wraps }, () => verifyDeviceWraps(event(chain, seq), wraps));

  // A server that wraps a key of its choosing to the joiner, or adds a recipient of its own.
  const serverKey = wrapToDevice({ vk: key32('server-chosen'), vaultId: VAULT_SHARED, keyEpoch: 1, recipient: bobCi.record, ephemeralSecret: seed('esk/server-chosen'), nonce: nonce('wrap/server-chosen') });
  const current4 = set('personal/4').filter((w) => w.key_epoch === 2);
  const tabletE1 = wrapsFor([aliceTablet], 1, 'add/personal/6/e1', VAULT_PERSONAL);
  return {
    version: 1,
    description:
      'Wrap sets of device-adding events (spec §4, §11). chains: shared and personal are the verified membership chains of membership.json (chains[0], chains[1]); personal_current_only is the personal chain up to its first rekey plus an owner device_add whose set delivers only the current epoch. verifyDeviceWraps(chains[chain][event_seq], wraps). Checks in order: the event is genesis, device_add or member_add; wraps parse; every rcpt is a device the event adds (forbidden); key_epoch in 1..event.key_epoch and (rcpt, key_epoch) unique; completeness: a recovery-authored device_add (sas "") carries at least one wrap (the bundle may predate later rekeys), any other event carries a wrap at event.key_epoch for every added device (older epochs optional); finally b64 sha256(utf8("akv1/wraps\\n") || cjson(wraps sorted by rcpt, then key_epoch)) == body.wraps_digest. Input order does not matter. cases MUST pass and every wrap MUST unwrap (with the recipient device kx_secret from membership.json) to vault_keys[chain][key_epoch]; invalid MUST fail with expect_error.',
    chains: CHAINS,
    vault_keys: { shared: vaultKeys(VAULT_SHARED, 3), personal: vaultKeys(VAULT_PERSONAL, 2), personal_current_only: vaultKeys(VAULT_PERSONAL, 2) },
    cases: [
      ok('genesis_every_genesis_device', 'shared', 0, set('shared/0')),
      ok('member_add', 'shared', 1, set('shared/1')),
      ok('owner_device_add', 'shared', 3, set('shared/3')),
      ok('owner_device_add_every_epoch', 'personal', 4, set('personal/4')),
      ok('owner_device_add_any_order', 'personal', 4, [...set('personal/4')].reverse()),
      ok('owner_device_add_current_epoch_only', 'personal_current_only', 4, TABLET_CURRENT_ONLY),
      ok('recovery_device_add', 'personal', 1, set('personal/1')),
      ok('recovery_device_add_bundle_epochs_only', 'personal', 6, set('personal/6')),
    ],
    invalid: [
      bad('injected_key_for_joiner', 'bad_request', 'shared', 3, [serverKey]),
      bad('injected_recipient', 'forbidden', 'shared', 3, [...set('shared/3'), ...wrapsFor([stranger], 1, 'device-add-inj')]),
      bad('wrap_to_existing_member', 'forbidden', 'shared', 3, [...set('shared/3'), ...wrapsFor([alicePhone], 1, 'device-add-existing')]),
      bad('dropped_wrap_from_signed_set', 'bad_request', 'personal', 4, current4),
      bad('missing_current_epoch', 'bad_request', 'personal', 4, set('personal/4').filter((w) => w.key_epoch === 1)),
      bad('missing_genesis_device', 'bad_request', 'shared', 0, set('shared/0').slice(0, 1)),
      bad('epoch_ahead_of_event', 'bad_request', 'personal', 1, [...set('personal/1'), ...wrapsFor([aliceNewPhone], 2, 'device-add-ahead', VAULT_PERSONAL)]),
      bad('duplicate_wrap', 'bad_request', 'shared', 0, [...set('shared/0'), set('shared/0')[0]!]),
      bad('recovery_set_empty', 'bad_request', 'personal', 1, []),
      bad('recovery_set_extra_epoch_not_signed', 'bad_request', 'personal', 6, [...set('personal/6'), ...tabletE1]),
      bad('event_does_not_add_devices', 'bad_request', 'shared', 5, []),
      bad('rekey_event', 'bad_request', 'shared', 6, []),
      bad('unsupported_wrap_alg', 'unsupported_version', 'shared', 3, [{ ...set('shared/3')[0]!, alg: 'x448-xc20p' }]),
    ],
  };
}

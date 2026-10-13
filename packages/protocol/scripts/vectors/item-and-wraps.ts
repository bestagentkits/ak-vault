/** item.json, wrap-x25519.json, wrap-password.json, wrap-recovery.json */
import {
  cjson,
  decodeRecoveryKey,
  deriveItemKey,
  deriveRecoveryKek,
  derivePasswordKek,
  encodeRecoveryKey,
  itemAad,
  openItem,
  sealItem,
  unwrapFromDevice,
  unwrapWithPassword,
  unwrapWithRecoveryKey,
  wrapToDevice,
  wrapWithPassword,
  wrapWithRecoveryKey,
  x25519Shared,
  b64decode,
  type ItemContext,
  type ItemPayload,
  type TombstonePayload,
} from '../../src/index.js';
import { hkdf32 } from '../../src/hkdf.js';
import { concatBytes, utf8Encode } from '../../src/bytes.js';
import { alicePhone, b64, bobLaptop, flipByte, id, key32, negative, nonce, seed, VAULT_SHARED } from './fixtures.js';

const VK = key32('vk/epoch1');

export function itemVectors(): Record<string, unknown> {
  const base = { vault_id: VAULT_SHARED, key_epoch: 1, author: alicePhone.record.device_id };
  const inputs: { name: string; ctx: ItemContext; payload: ItemPayload | TombstonePayload }[] = [
    {
      name: 'live_item',
      ctx: { ...base, item_id: id('item/github'), base_revision: 0, tombstone: false },
      payload: { name: 'GITHUB_TOKEN', value: 'ghp_example_not_a_real_token', meta: { tags: ['ci', 'github'], description: 'Deploy token' }, sensitivity: 'normal' },
    },
    {
      name: 'high_sensitivity_unicode',
      ctx: { ...base, item_id: id('item/db'), base_revision: 4, tombstone: false },
      payload: { name: 'DB_PASSWORD', value: 'pässwörd\n"quoted"', meta: {}, sensitivity: 'high' },
    },
    { name: 'tombstone', ctx: { ...base, item_id: id('item/github'), base_revision: 1, tombstone: true }, payload: { deleted: true } },
  ];
  const cases = inputs.map(({ name, ctx, payload }) => ({
    name,
    vk: b64(VK),
    ...ctx,
    item_key: b64(deriveItemKey(VK, ctx.vault_id, ctx.item_id, ctx.key_epoch)),
    aad_cjson: cjson(itemAad(ctx)),
    payload,
    plaintext: cjson(payload),
    nonce: b64(nonce(`item/${name}`)),
    env: sealItem({ ...ctx, vk: VK, payload, nonce: nonce(`item/${name}`) }),
  }));
  const live = cases[0]!;
  const ctx0 = inputs[0]!.ctx;
  const neg = (name: string, code: string, ctx: ItemContext, env: unknown) =>
    negative(name, code, { vk: b64(VK), ...ctx, env }, () => openItem({ ...ctx, vk: VK, env }));
  return {
    version: 1,
    description:
      'Item encryption (spec §3, §3.2). item_key = HKDF-SHA256(ikm=vk, salt=b64decode(vault_id), info=utf8("akv1/item-key\\n")||cjson({item_id,key_epoch}), 32). Envelope kid is the epoch tag "e<key_epoch>", aad = cjson of the item AAD object (aad_cjson). cases: sealing `payload` (plaintext = cjson(payload)) with `nonce` MUST produce `env`; opening MUST return `payload`. invalid: opening `env` under the given context MUST fail with expect_error.',
    cases,
    invalid: [
      neg('moved_to_other_item', 'decrypt_failed', { ...ctx0, item_id: id('item/other') }, live.env),
      neg('base_revision_changed', 'decrypt_failed', { ...ctx0, base_revision: 1 }, live.env),
      neg('tombstone_flag_flipped', 'decrypt_failed', { ...ctx0, tombstone: true }, live.env),
      neg('author_changed', 'decrypt_failed', { ...ctx0, author: bobLaptop.record.device_id }, live.env),
      neg('kid_not_epoch_tag', 'bad_request', ctx0, { ...live.env, kid: 'e2' }),
      neg('tampered_ct', 'decrypt_failed', ctx0, { ...live.env, ct: flipByte(live.env.ct, 3) }),
    ],
  };
}

export function x25519WrapVectors(): Record<string, unknown> {
  const esk = seed('wrap/esk');
  const wrap = wrapToDevice({ vk: VK, vaultId: VAULT_SHARED, keyEpoch: 1, recipient: alicePhone.record, ephemeralSecret: esk, nonce: nonce('wrap/x25519') });
  const rcptPub = b64decode(alicePhone.record.kx_pub);
  const shared = x25519Shared(esk, rcptPub);
  const wrapKey = hkdf32(shared, concatBytes(b64decode(wrap.epk), rcptPub), utf8Encode('akv1/wrap/x25519'));
  const unwrapArgs = { vaultId: VAULT_SHARED, deviceId: alicePhone.record.device_id, kxSecret: alicePhone.kxSecret };
  const neg = (name: string, code: string, w: unknown, args = unwrapArgs) =>
    negative(name, code, { vault_id: args.vaultId, device_id: args.deviceId, kx_secret: b64(args.kxSecret), wrap: w }, () => unwrapFromDevice({ ...args, wrap: w }));
  // Point of order 8 on Curve25519 (RFC 7748 §5 / libsodium blocklist): X25519 output is all zero.
  const lowOrder = b64(Uint8Array.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'.match(/../g)!.map((h) => parseInt(h, 16))));
  return {
    version: 1,
    description:
      'Device key wrap x25519-xc20p (spec §3.3). case: shared = X25519(ephemeral_secret, recipient.kx_pub); wrap_key = HKDF-SHA256(shared, salt=epk||kx_pub, info="akv1/wrap/x25519", 32); ct = XC20P(wrap_key, nonce, vk, aad={ctx:"akv1/wrap",vault_id,key_epoch,recipient}). Wrapping MUST produce `wrap`; unwrapping with the recipient kx_secret MUST return `vk`. invalid: unwrap MUST fail with expect_error (all-zero shared secret from a low-order epk is bad_request).',
    cases: [
      {
        name: 'wrap_to_device',
        vk: b64(VK),
        vault_id: VAULT_SHARED,
        key_epoch: 1,
        recipient: { device_id: alicePhone.record.device_id, kx_pub: alicePhone.record.kx_pub, kx_secret: b64(alicePhone.kxSecret) },
        ephemeral_secret: b64(esk),
        epk: wrap.epk,
        shared: b64(shared),
        wrap_key: b64(wrapKey),
        nonce: b64(nonce('wrap/x25519')),
        wrap,
      },
    ],
    invalid: [
      neg('wrong_recipient_key', 'decrypt_failed', wrap, { ...unwrapArgs, kxSecret: bobLaptop.kxSecret }),
      neg('rcpt_not_self', 'forbidden', wrap, { ...unwrapArgs, deviceId: bobLaptop.record.device_id }),
      neg('key_epoch_changed', 'decrypt_failed', { ...wrap, key_epoch: 2 }),
      neg('wrong_vault', 'decrypt_failed', wrap, { ...unwrapArgs, vaultId: id('vault/other') }),
      neg('all_zero_epk', 'bad_request', { ...wrap, epk: b64(new Uint8Array(32)) }),
      neg('low_order_epk', 'bad_request', { ...wrap, epk: lowOrder }),
      neg('unsupported_version', 'unsupported_version', { ...wrap, v: 2 }),
    ],
  };
}

export function passwordWrapVectors(): Record<string, unknown> {
  const params = { t: 2, m: 19_456, p: 1 };
  const cases = [
    { name: 'ascii_password', password: 'correct horse battery staple' },
    { name: 'nfd_input_normalized_to_nfc', password: 'café ünïcödé' },
  ].map((c) => {
    const salt = seed(`pw/salt/${c.name}`).slice(0, 16);
    const wrap = wrapWithPassword({ vk: VK, vaultId: VAULT_SHARED, keyEpoch: 1, password: c.password, params, salt, nonce: nonce(`pw/${c.name}`) });
    return { name: c.name, password: c.password, password_nfc: c.password.normalize('NFC'), vault_id: VAULT_SHARED, key_epoch: 1, salt: b64(salt), ...params, kek: b64(derivePasswordKek(c.password, salt, params)), nonce: b64(nonce(`pw/${c.name}`)), vk: b64(VK), wrap, needs_upgrade: true };
  });
  const wrap = cases[0]!.wrap;
  const neg = (name: string, code: string, w: unknown, password = cases[0]!.password) =>
    negative(name, code, { vault_id: VAULT_SHARED, password, wrap: w }, () => unwrapWithPassword({ wrap: w, vaultId: VAULT_SHARED, password }));
  return {
    version: 1,
    description:
      'Password wrap argon2id-xc20p (spec §3.4). kek = Argon2id v1.3(utf8(NFC(password)), salt, t, m KiB, p, 32); ct = XC20P(kek, nonce, vk, aad={ctx:"akv1/pw-wrap",vault_id,key_epoch,t,m,p}). cases MUST reproduce `kek` and `wrap`; unwrap MUST return `vk` and flag needs_upgrade when params are weaker than defaults (t=3,m=65536,p=1). invalid: parameter bounds (t<2, t>10, m<19456, m>1048576, p<1, p>16) MUST be rejected before any KDF work.',
    cases,
    invalid: [
      neg('t_below_min', 'bad_request', { ...wrap, t: 1 }),
      neg('t_above_max', 'bad_request', { ...wrap, t: 11 }),
      neg('m_below_min', 'bad_request', { ...wrap, m: 19_455 }),
      neg('m_above_max', 'bad_request', { ...wrap, m: 1_048_577 }),
      neg('p_zero', 'bad_request', { ...wrap, p: 0 }),
      neg('p_above_max', 'bad_request', { ...wrap, p: 17 }),
      neg('wrong_password', 'decrypt_failed', wrap, 'Correct horse battery staple'),
      neg('key_epoch_changed', 'decrypt_failed', { ...wrap, key_epoch: 2 }),
      neg('unknown_alg', 'unsupported_version', { ...wrap, alg: 'scrypt-xc20p' }),
    ],
  };
}

export function recoveryWrapVectors(): Record<string, unknown> {
  const rk = seed('recovery/rk');
  const display = encodeRecoveryKey(rk);
  const wrap = wrapWithRecoveryKey({ vk: VK, vaultId: VAULT_SHARED, keyEpoch: 1, rk, nonce: nonce('rk/wrap') });
  const aliasInput = display.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/-/g, ' ');
  const zeroKey = new Uint8Array(32);
  const badPadding = display.slice(0, -1) + '1';
  const negDecode = (name: string, input: string) => negative(name, 'bad_request', { display: input }, () => decodeRecoveryKey(input));
  return {
    version: 1,
    description:
      'Recovery key (spec §3.4). display = Crockford base32 of rk (MSB-first, uppercase, 52 symbols, groups of 4 joined by "-"). Decoding is case-insensitive, ignores "-" and spaces, maps I/L->1 and O->0. kek = HKDF-SHA256(rk, salt=utf8("akv1"), info="akv1/recovery-kek", 32); ct = XC20P(kek, nonce, vk, aad={ctx:"akv1/rk-wrap",vault_id,key_epoch}). invalid_display: decoding MUST fail; invalid: unwrap MUST fail with expect_error.',
    cases: [
      { name: 'recovery_wrap', rk: b64(rk), display, kek: b64(deriveRecoveryKek(rk)), vault_id: VAULT_SHARED, key_epoch: 1, nonce: b64(nonce('rk/wrap')), vk: b64(VK), wrap },
      { name: 'all_zero_display', rk: b64(zeroKey), display: encodeRecoveryKey(zeroKey) },
    ],
    decode_aliases: [{ input: aliasInput, rk: b64(decodeRecoveryKey(aliasInput)) }],
    invalid_display: [
      negDecode('invalid_symbol_u', display.slice(0, -2) + 'U' + display.slice(-1)),
      negDecode('too_short', display.slice(0, -1)),
      negDecode('non_zero_padding_bits', badPadding),
    ],
    invalid: [
      negative('wrong_recovery_key', 'decrypt_failed', { vault_id: VAULT_SHARED, rk: b64(zeroKey), wrap }, () => unwrapWithRecoveryKey({ wrap, vaultId: VAULT_SHARED, rk: zeroKey })),
      negative('key_epoch_changed', 'decrypt_failed', { vault_id: VAULT_SHARED, rk: b64(rk), wrap: { ...wrap, key_epoch: 3 } }, () =>
        unwrapWithRecoveryKey({ wrap: { ...wrap, key_epoch: 3 }, vaultId: VAULT_SHARED, rk }),
      ),
    ],
  };
}

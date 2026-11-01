/** kit-backup.json */
import { argon2id } from '@noble/hashes/argon2.js';
import { b64decode, cjson, KIT_BACKUP_ALG, kitBackupFileBytes, openKitBackup, sealKitBackup, type KitBackupFile, type KitBackupKit } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { utf8Encode } from '../../src/bytes.js';
import { hkdf32 } from '../../src/hkdf.js';
import { b64, flipByte, id, key32, negative, nonce, seed, VAULT_PERSONAL } from './fixtures.js';

const PARAMS = { t: 3, m: 65_536, p: 1 };
const PASSPHRASE = 'correct horse battery staple 7';
const SIGN_PUB = b64(seed('kit-backup/recovery-sign-pub'));
const OTHER_SIGN_PUB = b64(seed('kit-backup/other-recovery-sign-pub'));
const SALT = seed('kit-backup/salt').slice(0, 16);

const KIT: KitBackupKit = {
  vault_id: VAULT_PERSONAL,
  account: 'acct_alice',
  vault_origin: 'https://vault.example.test',
  recovery_key: b64(key32('kit-backup/recovery-key')),
};

const seal = (label: string, kit: KitBackupKit, passphrase: string, signPub = SIGN_PUB) =>
  sealKitBackup({ kit, recoverySignPub: signPub, passphrase, params: PARAMS, salt: seed(`kit-backup/salt/${label}`).slice(0, 16), nonce: nonce(`kit-backup/${label}`) });

/** Encrypt an arbitrary plaintext under the header exactly as sealKitBackup would (negative vectors). */
function rawSeal(label: string, plaintext: Uint8Array, header = { vault_id: KIT.vault_id, account: KIT.account }): KitBackupFile {
  const salt = seed(`kit-backup/salt/${label}`).slice(0, 16);
  const key = hkdf32(argon2id(utf8Encode(PASSPHRASE), salt, { ...PARAMS, dkLen: 32 }), utf8Encode('akv1'), utf8Encode('akv1/kit-backup-key'));
  const n = nonce(`kit-backup/${label}`);
  const aad = { ctx: 'akv1/kit-backup', ...header, recovery_sign_pub: SIGN_PUB, ...PARAMS };
  return { v: 1, alg: KIT_BACKUP_ALG, ...header, recovery_sign_pub: SIGN_PUB, s: b64(salt), ...PARAMS, n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) };
}

export function kitBackupVectors(): Record<string, unknown> {
  const EXPECTED = { account: KIT.account, vault_id: KIT.vault_id, recovery_sign_pub: SIGN_PUB };
  const ok = (name: string, kit: KitBackupKit, passphrase: string, passphraseInput = passphrase, expected: Record<string, string> = EXPECTED) => {
    const file = seal(name, kit, passphrase);
    const text = new TextDecoder().decode(kitBackupFileBytes(file));
    const opened = openKitBackup(text, passphraseInput, expected as never);
    if (cjson(opened) !== cjson(kit)) throw new Error(`kit-backup ${name}: round trip mismatch`);
    return {
      name,
      kit,
      recovery_sign_pub: SIGN_PUB,
      passphrase,
      ...(passphraseInput === passphrase ? {} : { passphrase_input: passphraseInput }),
      params: PARAMS,
      salt: b64(seed(`kit-backup/salt/${name}`).slice(0, 16)),
      nonce: b64(nonce(`kit-backup/${name}`)),
      expected,
      file,
      file_text: text,
      // The same file with reordered keys and inner whitespace: the opener accepts any JSON in the data model.
      file_text_reformatted: JSON.stringify(Object.fromEntries(Object.entries(file).reverse()), null, 2),
    };
  };
  const base = seal('base', KIT, PASSPHRASE);
  const baseText = new TextDecoder().decode(kitBackupFileBytes(base));
  const bad = (name: string, code: string, input: { file?: unknown; file_text?: string; trailing_spaces?: number }, passphrase = PASSPHRASE, expected: Record<string, string> = EXPECTED) =>
    negative(name, code, { passphrase, expected, ...input }, () => {
      const pad = ' '.repeat(input.trailing_spaces ?? 0);
      return openKitBackup(input.file_text !== undefined ? input.file_text + pad : (input.file as object), passphrase, expected as never);
    });
  const inner = (o: Record<string, unknown>) => utf8Encode(cjson(o));
  const innerBase = { v: 1, ...KIT };
  const sealBad = (name: string, code: string, data: Record<string, unknown>, run: () => unknown) => negative(name, code, data, run);
  const args = (over: Record<string, unknown> = {}) => ({ kit: KIT, recoverySignPub: SIGN_PUB, passphrase: PASSPHRASE, params: PARAMS, ...over }) as Parameters<typeof sealKitBackup>[0];
  const sealCase = (name: string, code: string, over: Record<string, unknown>, show: Record<string, unknown> = over) =>
    sealBad(name, code, { kit: KIT, recovery_sign_pub: SIGN_PUB, passphrase: PASSPHRASE, params: PARAMS, ...show }, () => sealKitBackup(args(over)));

  return {
    version: 1,
    description:
      'Recovery kit backup (spec §3.12). file = cjson({"v":1,"alg":"argon2id-xc20p-kit","vault_id","account","recovery_sign_pub","s","t","m","p","n","ct"}); ' +
      'K_pw = Argon2id(NFC(passphrase), s, t, m, p, 32); key = HKDF-SHA256(ikm=K_pw, salt=utf8("akv1"), info=utf8("akv1/kit-backup-key"), L=32); ' +
      'aad = cjson({"ctx":"akv1/kit-backup","vault_id","account","recovery_sign_pub","t","m","p"}); ct = XChaCha20-Poly1305(key, n, cjson({"v":1,"vault_id","account","vault_origin","recovery_key"}), aad). ' +
      'Argon2id bounds t 3..10, m 65536..524288 KiB, p 1..4, checked before any KDF work. Opening takes the expected account (and optionally vault_id and recovery_sign_pub); a mismatch is bad_request before any KDF work. ' +
      'Sealing requires a passphrase of at least 12 code points after NFC; opening accepts any non-empty one. All passphrases, keys and identifiers here are synthetic.',
    cases: [
      ok('ascii_passphrase', KIT, PASSPHRASE),
      ok('generated_shape_passphrase', { ...KIT, vault_origin: 'https://vault.agentkit.test' }, 'K7QM-3XPD-9TVA-C2HW-NE4R-8BJF-ZY6G-0S5H'),
      ok('nfd_input_matches_nfc', KIT, 'Pässwörd-für-backup-ü', 'Pässwörd-für-backup-ü'),
      ok('maximum_length_kit', { ...KIT, account: 'a'.repeat(256), vault_origin: `https://${'o'.repeat(248)}` }, PASSPHRASE, PASSPHRASE, { ...EXPECTED, account: 'a'.repeat(256) }),
      ok('account_and_vault_only', KIT, PASSPHRASE, PASSPHRASE, { account: KIT.account }),
    ],
    invalid: [
      bad('wrong_passphrase', 'decrypt_failed', { file: base }, PASSPHRASE + 'x'),
      bad('case_changed_passphrase', 'decrypt_failed', { file: base }, PASSPHRASE.toUpperCase()),
      bad('wrong_account_expected', 'bad_request', { file: base }, PASSPHRASE, { ...EXPECTED, account: 'acct_mallory' }),
      bad('wrong_vault_expected', 'bad_request', { file: base }, PASSPHRASE, { ...EXPECTED, vault_id: id('kit-backup/other-vault') }),
      bad('stale_recovery_key_expected', 'bad_request', { file: base }, PASSPHRASE, { ...EXPECTED, recovery_sign_pub: OTHER_SIGN_PUB }),
      bad('header_vault_relabelled', 'decrypt_failed', { file: { ...base, vault_id: id('kit-backup/other-vault') } }, PASSPHRASE, { account: KIT.account }),
      bad('header_account_relabelled', 'decrypt_failed', { file: { ...base, account: 'acct_mallory' } }, PASSPHRASE, { account: 'acct_mallory' }),
      bad('header_sign_pub_relabelled', 'decrypt_failed', { file: { ...base, recovery_sign_pub: OTHER_SIGN_PUB } }, PASSPHRASE, { account: KIT.account }),
      bad('param_t_relabelled', 'decrypt_failed', { file: { ...base, t: 4 } }),
      bad('param_m_relabelled', 'decrypt_failed', { file: { ...base, m: 131_072 } }),
      bad('param_p_relabelled', 'decrypt_failed', { file: { ...base, p: 2 } }),
      bad('ciphertext_flipped', 'decrypt_failed', { file: { ...base, ct: flipByte(base.ct, 3) } }),
      bad('nonce_flipped', 'decrypt_failed', { file: { ...base, n: flipByte(base.n, 0) } }),
      bad('salt_flipped', 'decrypt_failed', { file: { ...base, s: flipByte(base.s, 0) } }),
      bad('tag_truncated', 'decrypt_failed', { file: { ...base, ct: b64(b64decode(base.ct).slice(0, -1)) } }),
      bad('extra_key', 'bad_request', { file: { ...base, note: 'x' } }),
      bad('missing_key', 'bad_request', { file: Object.fromEntries(Object.entries(base).filter(([k]) => k !== 'p')) }),
      bad('unknown_alg', 'unsupported_version', { file: { ...base, alg: 'argon2id-xc20p' } }),
      bad('version_2', 'unsupported_version', { file: { ...base, v: 2 } }),
      bad('t_below_minimum', 'bad_request', { file: { ...base, t: 2 } }),
      bad('m_below_minimum', 'bad_request', { file: { ...base, m: 19_456 } }),
      bad('m_above_maximum', 'bad_request', { file: { ...base, m: 1_048_576 } }),
      bad('t_above_maximum', 'bad_request', { file: { ...base, t: 11 } }),
      bad('p_above_maximum', 'bad_request', { file: { ...base, p: 5 } }),
      bad('short_salt', 'bad_request', { file: { ...base, s: b64(new Uint8Array(15)) } }),
      bad('short_nonce', 'bad_request', { file: { ...base, n: b64(new Uint8Array(23)) } }),
      bad('short_sign_pub', 'bad_request', { file: { ...base, recovery_sign_pub: b64(new Uint8Array(31)) } }, PASSPHRASE, { account: KIT.account }),
      bad('short_ct', 'bad_request', { file: { ...base, ct: b64(new Uint8Array(15)) } }),
      bad('long_ct', 'bad_request', { file: { ...base, ct: b64(new Uint8Array(1281)) } }),
      bad('empty_passphrase', 'bad_request', { file: base }, ''),
      bad('not_json', 'bad_request', { file_text: 'AKVAULT recovery kit' }),
      bad('duplicate_key', 'bad_request', { file_text: baseText.replace('"v":1,', '"v":1,"v":1,') }),
      bad('oversize_file', 'bad_request', { file_text: baseText, trailing_spaces: 4096 }),
      bad('payload_vault_disagrees', 'bad_request', { file: rawSeal('payload_vault', inner({ ...innerBase, vault_id: id('kit-backup/other-vault') })) }),
      bad('payload_account_disagrees', 'bad_request', { file: rawSeal('payload_account', inner({ ...innerBase, account: 'acct_mallory' })) }),
      bad('payload_not_canonical', 'bad_request', { file: rawSeal('payload_noncanonical', utf8Encode(JSON.stringify(innerBase, null, 1))) }),
      bad('payload_extra_key', 'bad_request', { file: rawSeal('payload_extra', inner({ ...innerBase, note: 'x' })) }),
      bad('payload_version_2', 'unsupported_version', { file: rawSeal('payload_v2', inner({ ...innerBase, v: 2 })) }),
      bad('payload_short_key', 'bad_request', { file: rawSeal('payload_short_key', inner({ ...innerBase, recovery_key: b64(new Uint8Array(31)) })) }),
      bad('payload_missing_origin', 'bad_request', { file: rawSeal('payload_no_origin', inner({ v: 1, vault_id: KIT.vault_id, account: KIT.account, recovery_key: KIT.recovery_key })) }),
    ],
    seal_invalid: [
      sealCase('passphrase_too_short', 'bad_request', { passphrase: 'short-pass1' }),
      sealCase('passphrase_empty', 'bad_request', { passphrase: '' }),
      sealCase('passphrase_too_long', 'bad_request', { passphrase: 'p'.repeat(1025) }, { passphrase: '', passphrase_fill: 'p', passphrase_length: 1025 }),
      sealCase('recovery_key_short', 'bad_request', { kit: { ...KIT, recovery_key: b64(new Uint8Array(31)) } }),
      sealCase('kit_extra_key', 'bad_request', { kit: { ...KIT, note: 'x' } }),
      sealCase('origin_not_ascii', 'bad_request', { kit: { ...KIT, vault_origin: 'https://välue.example' } }),
      sealCase('origin_empty', 'bad_request', { kit: { ...KIT, vault_origin: '' } }),
      sealCase('sign_pub_short', 'bad_request', { recoverySignPub: b64(new Uint8Array(31)) }, { recovery_sign_pub: b64(new Uint8Array(31)) }),
      sealCase('t_below_minimum', 'bad_request', { params: { t: 2, m: 65_536, p: 1 } }, { params: { t: 2, m: 65_536, p: 1 } }),
      sealCase('m_below_minimum', 'bad_request', { params: { t: 3, m: 19_456, p: 1 } }, { params: { t: 3, m: 19_456, p: 1 } }),
      sealCase('m_above_maximum', 'bad_request', { params: { t: 3, m: 524_289, p: 1 } }, { params: { t: 3, m: 524_289, p: 1 } }),
      sealCase('p_above_maximum', 'bad_request', { params: { t: 3, m: 65_536, p: 5 } }, { params: { t: 3, m: 65_536, p: 5 } }),
    ],
  };
}

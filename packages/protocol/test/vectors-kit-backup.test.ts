/** Recovery kit backup vectors (spec §3.12). */
import { describe, expect, it } from 'vitest';
import { b64decode, generateBackupPassphrase, kitBackupFileBytes, openKitBackup, parseKitBackupFile, sealKitBackup } from '../src/index.js';
import { expectCode, loadVector, named } from './helpers.js';

describe('kit-backup.json', () => {
  const v = loadVector('kit-backup.json');
  it.each(named(v.cases))('reproduces and opens %s', (_n, c) => {
    const file = sealKitBackup({ kit: c.kit, recoverySignPub: c.recovery_sign_pub, passphrase: c.passphrase, params: c.params, salt: b64decode(c.salt), nonce: b64decode(c.nonce) });
    expect(file).toEqual(c.file);
    expect(new TextDecoder().decode(kitBackupFileBytes(file))).toBe(c.file_text);
    expect(openKitBackup(c.file_text, c.passphrase_input ?? c.passphrase, c.expected)).toEqual(c.kit);
    expect(openKitBackup(new TextEncoder().encode(`${c.file_text}\n`), c.passphrase, c.expected)).toEqual(c.kit);
    expect(openKitBackup(c.file_text_reformatted, c.passphrase, c.expected)).toEqual(c.kit);
    expect(openKitBackup(c.file, c.passphrase, c.expected)).toEqual(c.kit);
  });
  it.each(named(v.invalid))('refuses to open %s', (_n, c) => {
    const input = c.file_text !== undefined ? c.file_text + ' '.repeat(c.trailing_spaces ?? 0) : c.file;
    expectCode(() => openKitBackup(input, c.passphrase, c.expected), c.expect_error);
  });
  it.each(named(v.seal_invalid))('refuses to seal %s', (_n, c) => {
    const passphrase = c.passphrase_fill === undefined ? c.passphrase : c.passphrase_fill.repeat(c.passphrase_length);
    expectCode(() => sealKitBackup({ kit: c.kit, recoverySignPub: c.recovery_sign_pub, passphrase, params: c.params }), c.expect_error);
  });
  it('fresh seals of one kit differ and both open; the file stays under the size cap', () => {
    const c = v.cases[0];
    const args = { kit: c.kit, recoverySignPub: c.recovery_sign_pub, passphrase: c.passphrase, params: c.params };
    const a = sealKitBackup(args);
    const b = sealKitBackup(args);
    expect(a.s).not.toBe(b.s);
    expect(a.n).not.toBe(b.n);
    expect(a.ct).not.toBe(b.ct);
    expect(kitBackupFileBytes(a).length).toBeLessThan(1024);
    expect(openKitBackup(kitBackupFileBytes(b), c.passphrase, c.expected)).toEqual(c.kit);
  });
  it('never carries the recovery key or origin outside the ciphertext', () => {
    const c = v.cases[0];
    const text = c.file_text as string;
    expect(text).not.toContain(c.kit.recovery_key);
    expect(text).not.toContain(c.kit.vault_origin);
    expect(text).not.toContain(c.passphrase);
  });
  it('parses its own output and freezes the opened kit', () => {
    const c = v.cases[0];
    expect(parseKitBackupFile(c.file)).toEqual(c.file);
    expect(Object.isFrozen(openKitBackup(c.file_text, c.passphrase, c.expected))).toBe(true);
  });
  it('generates distinct 160-bit passphrases in the documented shape that seal', () => {
    const a = generateBackupPassphrase();
    const b = generateBackupPassphrase();
    expect(a).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(a).not.toBe(b);
    const c = v.cases[0];
    expect(() => sealKitBackup({ kit: c.kit, recoverySignPub: c.recovery_sign_pub, passphrase: a, params: c.params })).not.toThrow();
  });
});

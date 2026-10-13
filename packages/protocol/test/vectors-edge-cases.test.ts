/** Reproduce edge-cases.json: ASCII-only recovery keys, X25519 key lengths, strict Ed25519. */
import { describe, expect, it } from 'vitest';
import { b64decode, b64encode, decodeRecoveryKey, kxKeyPairFromSecret, unwrapFromDevice, verifyObject, wrapToDevice, x25519Shared } from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

describe('edge-cases.json', () => {
  const v = loadVector('edge-cases.json');
  it.each(named(v.recovery_key_display_valid))('decodes %s', (_n, c: Vec) => {
    expect(b64encode(decodeRecoveryKey(c.input))).toBe(c.rk);
  });
  it.each(named(v.recovery_key_display_invalid))('rejects display %s', (_n, c: Vec) => {
    expectCode(() => decodeRecoveryKey(c.display), c.expect_error);
  });
  it.each(named(v.x25519_public_key_invalid))('rejects kx secret %s', (_n, c: Vec) => {
    expectCode(() => kxKeyPairFromSecret(b64decode(c.secret)), c.expect_error);
  });
  it.each(named(v.x25519_shared_invalid))('rejects X25519 %s', (_n, c: Vec) => {
    expectCode(() => x25519Shared(b64decode(c.secret), b64decode(c.public_key)), c.expect_error);
  });
  it.each(named(v.unwrap_from_device_invalid))('rejects unwrap %s', (_n, c: Vec) => {
    expectCode(() => unwrapFromDevice({ wrap: c.wrap, vaultId: c.vault_id, deviceId: c.device_id, kxSecret: b64decode(c.kx_secret) }), c.expect_error);
  });
  it.each(named(v.wrap_to_device_invalid))('rejects wrap %s', (_n, c: Vec) => {
    expectCode(
      () =>
        wrapToDevice({
          vk: b64decode(c.vk),
          vaultId: c.vault_id,
          keyEpoch: c.key_epoch,
          recipient: c.recipient,
          ephemeralSecret: b64decode(c.ephemeral_secret),
          nonce: b64decode(c.nonce),
        }),
      c.expect_error,
    );
  });
  it.each(named(v.ed25519_valid))('verifies %s', (_n, c: Vec) => {
    expect(() => verifyObject(c.context, c.object, c.public_key)).not.toThrow();
  });
  it.each(named(v.ed25519_invalid))('rejects signature %s', (_n, c: Vec) => {
    expectCode(() => verifyObject(c.context, c.object, c.public_key), c.expect_error);
  });
});

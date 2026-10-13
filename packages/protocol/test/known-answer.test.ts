/** RFC known-answer tests for the audited primitives exactly as this package uses them. */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { describe, expect, it } from 'vitest';
import { hkdf32 } from '../src/hkdf.js';
import { signKeyPairFromSeed, verifyDetached, x25519Shared, kxKeyPairFromSecret, utf8Encode } from '../src/index.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hex, toHex } from './helpers.js';

describe('RFC 8032 Ed25519', () => {
  const cases = [
    {
      sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      msg: '',
      sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    },
    {
      sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      msg: '72',
      sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    },
  ];
  it.each(cases)('test vector $pk', (c) => {
    expect(toHex(signKeyPairFromSeed(hex(c.sk)).publicKey)).toBe(c.pk);
    expect(toHex(ed25519.sign(hex(c.msg), hex(c.sk)))).toBe(c.sig);
    expect(ed25519.verify(hex(c.sig), hex(c.msg), hex(c.pk), { zip215: false })).toBe(true);
  });
  it('verifyDetached rejects malformed signatures without throwing', () => {
    expect(verifyDetached('akv1/record', {}, 'AAAA', new Uint8Array(32))).toBe(false);
  });
});

describe('RFC 7748 X25519', () => {
  it('§5.2 scalar multiplication', () => {
    const k = hex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const u = hex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    expect(toHex(x25519Shared(k, u))).toBe('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');
  });
  it('§6.1 Diffie-Hellman', () => {
    const a = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const b = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    expect(toHex(kxKeyPairFromSecret(a).publicKey)).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    expect(toHex(kxKeyPairFromSecret(b).publicKey)).toBe('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    expect(toHex(x25519Shared(a, kxKeyPairFromSecret(b).publicKey))).toBe(shared);
    expect(toHex(x25519Shared(b, kxKeyPairFromSecret(a).publicKey))).toBe(shared);
  });
});

describe('RFC 5869 HKDF-SHA256', () => {
  it('test case 1 (first 32 bytes of OKM)', () => {
    const okm = hkdf32(new Uint8Array(22).fill(0x0b), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'));
    expect(toHex(okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf');
  });
});

describe('XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha A.3.1)', () => {
  it('AEAD test vector', () => {
    const pt = utf8Encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    const key = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
    const nonce = Uint8Array.from({ length: 24 }, (_, i) => 0x40 + i);
    const out = xchacha20poly1305(key, nonce, hex('50515253c0c1c2c3c4c5c6c7')).encrypt(pt);
    expect(toHex(out)).toBe(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e' +
        'c0875924c1c7987947deafd8780acf49',
    );
  });
});

describe('RFC 9106 Argon2id', () => {
  it('§5.3 test vector', () => {
    const tag = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
      t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4),
    });
    expect(toHex(tag)).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });
});

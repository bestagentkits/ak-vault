/**
 * edge-cases.json: cross-implementation edge cases fixed by spec §11 —
 * ASCII-only recovery key decoding, wrong-length X25519 keys, and strict
 * RFC 8032 Ed25519 verification.
 *
 * Every invalid Ed25519 vector except `s_not_reduced` is accepted by a lenient
 * (ZIP-215, cofactored) verifier; the generator proves that, so each vector
 * pins a real divergence point rather than an obviously broken signature.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  SIGN_CONTEXT,
  concatBytes,
  decodeRecoveryKey,
  encodeRecoveryKey,
  kxKeyPairFromSecret,
  signDetached,
  signingInput,
  signKeyPairFromSeed,
  unwrapFromDevice,
  verifyObject,
  wrapToDevice,
  x25519Shared,
  type JsonObject,
} from '../../src/index.js';
import { alicePhone, b64, key32, negative, nonce, seed, VAULT_SHARED } from './fixtures.js';

const Point = ed25519.Point;
const L = Point.Fn.ORDER;
const CONTEXT = SIGN_CONTEXT.checkpoint;

function hex(h: string): Uint8Array {
  return Uint8Array.from((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
}

function toLE(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function fromLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number);
  return n;
}

/** RFC 8032 challenge k = SHA-512(R || A || M) mod L. */
function challenge(r: Uint8Array, a: Uint8Array, msg: Uint8Array): bigint {
  return fromLE(sha512(concatBytes(r, a, msg))) % L;
}

const IDENTITY = hex('0100000000000000000000000000000000000000000000000000000000000000');
const IDENTITY_Y_PLUS_P = hex('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
const IDENTITY_NEGATIVE_ZERO = hex('0100000000000000000000000000000000000000000000000000000000000080');
const ORDER2_NEGATIVE_ZERO = hex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
const TORSION8 = Point.fromBytes(hex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'));
const SMALL_ORDER: [string, string][] = [
  ['identity', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['order2', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['order4_a', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['order4_b', '0000000000000000000000000000000000000000000000000000000000000080'],
  ['order8_a', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['order8_b', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'],
  ['order8_c', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['order8_d', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'],
];

const signer = signKeyPairFromSeed(seed('edge/ed25519/signer'));
const signerScalar = ed25519.utils.getExtendedPublicKey(signer.secretKey).scalar % L;
const nonceScalar = fromLE(seed('edge/ed25519/r')) % L;

/**
 * Search the object counter `n` until `build` returns a signature (some
 * forgeries only work when k has a given residue), then emit the vector.
 */
function sigVector(name: string, pub: Uint8Array, build: (msg: Uint8Array) => Uint8Array | null, lenientAccepts: boolean): Record<string, unknown> {
  for (let n = 0; n < 256; n++) {
    const unsigned: JsonObject = { edge: name, n };
    const msg = signingInput(CONTEXT, unsigned);
    const sig = build(msg);
    if (!sig) continue;
    if (ed25519.verify(sig, msg, pub, { zip215: true }) !== lenientAccepts) throw new Error(`vector ${name}: unexpected lenient verifier result`);
    const object = { ...unsigned, sig: b64(sig) };
    return negative(name, 'invalid_signature', { context: CONTEXT, object, public_key: b64(pub) }, () => verifyObject(CONTEXT, object, pub));
  }
  throw new Error(`vector ${name}: no suitable counter found`);
}

function ed25519Invalid(): Record<string, unknown>[] {
  const A = signer.publicKey;
  const out = [
    sigVector('s_not_reduced', A, (msg) => {
      const sig = ed25519.sign(msg, signer.secretKey);
      return concatBytes(sig.subarray(0, 32), toLE(fromLE(sig.subarray(32)) + L));
    }, false),
  ];
  // Small-order public keys: R = identity, S = 0 verifies whenever [k]A is the identity.
  for (const [label, h] of SMALL_ORDER) {
    const pub = hex(h);
    const point = Point.fromBytes(pub);
    out.push(sigVector(`small_order_public_key_${label}`, pub, (msg) => (point.multiplyUnsafe(challenge(IDENTITY, pub, msg)).is0() ? concatBytes(IDENTITY, toLE(0n)) : null), true));
  }
  // Non-canonical encodings of small-order public keys.
  for (const [label, pub] of [['identity_y_plus_p', IDENTITY_Y_PLUS_P], ['identity_negative_zero', IDENTITY_NEGATIVE_ZERO], ['order2_negative_zero', ORDER2_NEGATIVE_ZERO]] as const) {
    const point = Point.fromBytes(pub, true);
    out.push(sigVector(`non_canonical_public_key_${label}`, pub, (msg) => (point.multiplyUnsafe(challenge(IDENTITY, pub, msg)).is0() ? concatBytes(IDENTITY, toLE(0n)) : null), true));
  }
  // Non-canonical R: [S]B - [k]A is the identity, but R is not its canonical encoding.
  for (const [label, r] of [['y_plus_p', IDENTITY_Y_PLUS_P], ['negative_zero', IDENTITY_NEGATIVE_ZERO]] as const) {
    out.push(sigVector(`non_canonical_r_${label}`, A, (msg) => concatBytes(r, toLE((challenge(r, A, msg) * signerScalar) % L)), true));
  }
  // R with a torsion component: only the cofactored equation holds.
  out.push(
    sigVector('r_with_torsion_component', A, (msg) => {
      const r = Point.BASE.multiply(nonceScalar).add(TORSION8).toBytes();
      return concatBytes(r, toLE((nonceScalar + challenge(r, A, msg) * signerScalar) % L));
    }, true),
  );
  // Mixed-order public key aB + T: only the cofactored equation holds (k not a multiple of 8).
  const mixed = Point.BASE.multiply(signerScalar).add(TORSION8).toBytes();
  out.push(
    sigVector('public_key_with_torsion_component', mixed, (msg) => {
      const r = Point.BASE.multiply(nonceScalar).toBytes();
      const k = challenge(r, mixed, msg);
      return k % 8n === 0n ? null : concatBytes(r, toLE((nonceScalar + k * signerScalar) % L));
    }, true),
  );
  return out;
}

/** A recovery key whose display contains the symbols the look-alike cases replace. */
function displayFixture(): { rk: Uint8Array; display: string } {
  for (let i = 0; i < 64; i++) {
    const rk = seed(`edge/recovery-key/${i}`);
    const display = encodeRecoveryKey(rk);
    if (display.includes('1') && display.includes('S') && /[2-9]/.test(display)) return { rk, display };
  }
  throw new Error('no recovery key fixture found');
}

function recoveryDisplayVectors(): { valid: unknown[]; invalid: unknown[] } {
  const { rk, display } = displayFixture();
  const digit = display.match(/[2-9]/)![0];
  const neg = (name: string, input: string) => negative(name, 'bad_request', { display: input }, () => decodeRecoveryKey(input));
  const valid = [
    { name: 'lowercase_tab_separated', input: display.toLowerCase().split('-').join('\t') },
    { name: 'crlf_and_vertical_tab_separated', input: display.split('-').join('\r\n\v') },
  ].map((c) => {
    if (b64(decodeRecoveryKey(c.input)) !== b64(rk)) throw new Error(`vector ${c.name}: decode mismatch`);
    return { ...c, rk: b64(rk) };
  });
  const invalid = [
    // U+0131 and U+017F upper-case to "I" and "S" under full Unicode case mapping.
    neg('dotless_i_for_1', display.replace('1', 'ı')),
    neg('long_s_for_s', display.replace('S', 'ſ')),
    neg('fullwidth_digit', display.replace(digit, String.fromCharCode(0xff10 + Number(digit)))),
    neg('no_break_space_separator', display.split('-').join(' ')),
    neg('ideographic_space_separator', display.split('-').join('　')),
  ];
  return { valid, invalid };
}

function x25519Vectors(): Record<string, unknown[]> {
  const short = seed('edge/x25519/short').slice(0, 31);
  const long = concatBytes(seed('edge/x25519/long'), new Uint8Array([1]));
  const good = seed('edge/x25519/secret');
  const goodPub = kxKeyPairFromSecret(good).publicKey;
  const vk = key32('edge/vk');
  const wrap = wrapToDevice({ vk, vaultId: VAULT_SHARED, keyEpoch: 1, recipient: alicePhone.record, ephemeralSecret: good, nonce: nonce('edge/wrap') });
  const recipient = { device_id: alicePhone.record.device_id, kx_pub: alicePhone.record.kx_pub };
  const wrapArgs = { vk: b64(vk), vault_id: VAULT_SHARED, key_epoch: 1, nonce: b64(nonce('edge/wrap')) };
  return {
    x25519_public_key_invalid: [
      ['secret_31_bytes', short],
      ['secret_33_bytes', long],
      ['secret_empty', new Uint8Array(0)],
    ].map(([name, secret]) => negative(name as string, 'bad_request', { secret: b64(secret as Uint8Array) }, () => kxKeyPairFromSecret(secret as Uint8Array))),
    x25519_shared_invalid: [
      ['secret_31_bytes', short, goodPub],
      ['public_key_31_bytes', good, goodPub.slice(0, 31)],
      ['public_key_33_bytes', good, concatBytes(goodPub, new Uint8Array([0]))],
    ].map(([name, secret, pub]) =>
      negative(name as string, 'bad_request', { secret: b64(secret as Uint8Array), public_key: b64(pub as Uint8Array) }, () => x25519Shared(secret as Uint8Array, pub as Uint8Array)),
    ),
    unwrap_from_device_invalid: [
      ['kx_secret_31_bytes', short],
      ['kx_secret_33_bytes', long],
    ].map(([name, kxSecret]) =>
      negative(name as string, 'bad_request', { vault_id: VAULT_SHARED, device_id: recipient.device_id, kx_secret: b64(kxSecret as Uint8Array), wrap }, () =>
        unwrapFromDevice({ wrap, vaultId: VAULT_SHARED, deviceId: recipient.device_id, kxSecret: kxSecret as Uint8Array }),
      ),
    ),
    wrap_to_device_invalid: [
      negative('ephemeral_secret_31_bytes', 'bad_request', { ...wrapArgs, recipient, ephemeral_secret: b64(short) }, () =>
        wrapToDevice({ vk, vaultId: VAULT_SHARED, keyEpoch: 1, recipient, ephemeralSecret: short, nonce: nonce('edge/wrap') }),
      ),
      negative('recipient_kx_pub_31_bytes', 'bad_request', { ...wrapArgs, recipient: { ...recipient, kx_pub: b64(goodPub.slice(0, 31)) }, ephemeral_secret: b64(good) }, () =>
        wrapToDevice({ vk, vaultId: VAULT_SHARED, keyEpoch: 1, recipient: { ...recipient, kx_pub: b64(goodPub.slice(0, 31)) }, ephemeralSecret: good, nonce: nonce('edge/wrap') }),
      ),
    ],
  };
}

export function edgeCaseVectors(): Record<string, unknown> {
  const display = recoveryDisplayVectors();
  const baseline: JsonObject = { edge: 'baseline', n: 0 };
  return {
    version: 1,
    description:
      'Cross-implementation edge cases (spec §11). recovery_key_display_valid: decodeRecoveryKey(input) MUST return rk; recovery_key_display_invalid: decoding is ASCII-only and MUST fail. x25519_*: wrong-length keys MUST fail with bad_request (public key derivation, X25519, unwrapFromDevice, wrapToDevice with recipient.kx_pub b64 and ephemeral_secret). ed25519_valid: verifyObject(context, object, public_key) MUST succeed; ed25519_invalid: MUST fail with invalid_signature under strict RFC 8032 (S < L, canonical A and R, no small-order A, cofactorless equation); all but s_not_reduced verify under a lenient ZIP-215 cofactored verifier.',
    recovery_key_display_valid: display.valid,
    recovery_key_display_invalid: display.invalid,
    ...x25519Vectors(),
    ed25519_valid: [
      { name: 'baseline', context: CONTEXT, object: { ...baseline, sig: signDetached(CONTEXT, baseline, signer.secretKey) }, public_key: b64(signer.publicKey) },
    ],
    ed25519_invalid: ed25519Invalid(),
  };
}

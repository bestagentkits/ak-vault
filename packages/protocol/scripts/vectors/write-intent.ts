/** write-intent.json */
import { cjson, deriveSealKeyPair, kxKeyPairFromSecret, openWriteIntent, x25519Shared, type SealedOrigin, type WriteIntentOperation, type WriteIntentTarget, type WriteIntentWire } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { concatBytes, utf8Encode } from '../../src/bytes.js';
import { hkdf32 } from '../../src/hkdf.js';
import { sealWriteIntentWithVectorValues } from '../../src/write-intent.js';
import { b64, BASE_TS, flipByte, id, key32, negative, nonce, seed, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

const ORIGIN: SealedOrigin = { kind: 'mcp', account: 'acct_alice', client_id: 'mcp-client-example', grant_id: 'grant_example_1' };
const TTL_MS = 600_000;
const sealPair = (epoch: number) => deriveSealKeyPair(key32(`vk/epoch${epoch}`), VAULT_SHARED, epoch);

/** Encrypt an arbitrary plaintext exactly as sealWriteIntent would (for negative vectors it refuses). */
function rawSeal(header: Omit<WriteIntentWire, 'v' | 'alg' | 'epk' | 'n' | 'ct'>, plaintext: Uint8Array, label: string): WriteIntentWire {
  const sealPub = sealPair(header.key_epoch).publicKey;
  const esk = seed(`write-intent/esk/${label}`);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, sealPub), concatBytes(epk, sealPub), utf8Encode('akv1/write-intent'));
  const aad = { ctx: 'akv1/write-intent', vault_id: header.vault_id, request_id: header.request_id, key_epoch: header.key_epoch, origin: header.origin, operation: header.operation, ts: header.ts, expires_at: header.expires_at };
  const n = nonce(`write-intent/${label}`);
  return { v: 1, alg: 'x25519-xc20p-seal', ...header, epk: b64(epk), n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) };
}

export function writeIntentVectors(): Record<string, unknown> {
  const seal = (label: string, operation: WriteIntentOperation, target: WriteIntentTarget, epoch = 3) =>
    sealWriteIntentWithVectorValues(
      sealPair(epoch).publicKey,
      { vaultId: VAULT_SHARED, keyEpoch: epoch, origin: ORIGIN, operation, ts: BASE_TS + 3_600_000, expiresAt: BASE_TS + 3_600_000 + TTL_MS, target },
      { requestId: id(`write-intent/${label}`), ephemeralSecret: seed(`write-intent/esk/${label}`), nonce: nonce(`write-intent/${label}`) },
    );
  const ok = (name: string, operation: WriteIntentOperation, target: WriteIntentTarget, epoch = 3) => {
    const wire = seal(name, operation, target, epoch);
    const opened = openWriteIntent(sealPair(epoch).secretKey, wire, { vaultId: VAULT_SHARED });
    if (cjson(opened.target) !== cjson(target)) throw new Error(`write-intent ${name}: round trip mismatch`);
    return { name, key_epoch: epoch, ephemeral_secret: b64(seed(`write-intent/esk/${name}`)), operation, target, plaintext: cjson(target), wire };
  };
  const bad = (name: string, code: string, wire: unknown, epoch = 3, vaultId = VAULT_SHARED) =>
    negative(name, code, { open_with_epoch: epoch, vault_id: vaultId, wire }, () => openWriteIntent(sealPair(epoch).secretKey, wire, { vaultId }));
  const create = ok('create', 'create', { name: 'STRIPE_SECRET_KEY', purpose: 'Billing service', sensitivity: 'high' });
  const w = create.wire;
  const header = { request_id: w.request_id, vault_id: w.vault_id, key_epoch: w.key_epoch, origin: w.origin, operation: w.operation, ts: w.ts, expires_at: w.expires_at };
  const pt = (s: string) => utf8Encode(s);
  const sealBad = (name: string, code: string, target: unknown) =>
    negative(name, code, { target }, () => seal(name, 'create', target as WriteIntentTarget));
  return {
    version: 1,
    description:
      'Write intents x25519-xc20p-seal (spec §3.8), sealed to seal_pub[e] of seal-key.json seal_keys (vault shared). The target is the secret name (and optional purpose and sensitivity) an MCP client asked a human to write; it never carries a value. ' +
      'epk = X25519(ephemeral_secret, 9); shared = X25519(ephemeral_secret, seal_pub) (all-zero: bad_request); key = HKDF-SHA256(ikm=shared, salt=epk || seal_pub, info=utf8("akv1/write-intent"), L=32); aad = cjson({"ctx":"akv1/write-intent","vault_id","request_id","key_epoch","origin","operation","ts","expires_at"}); ct = XChaCha20-Poly1305(key, n, cjson(target), aad). ' +
      'cases: sealWriteIntent with the given ephemeral_secret, nonce wire.n and request_id MUST reproduce wire byte for byte, and openWriteIntent(SealSK[key_epoch], wire, {vault_id}) MUST yield target. ' +
      'openWriteIntent order: parse (v or alg unknown: unsupported_version; exact keys, IDs, epk 32 B, n 24 B, ct 16..16400 B, origin as in sealed-op.json, operation "create" or "replace", ts, expires_at > ts: bad_request); vault_id other than expected (bad_request); all-zero shared secret (bad_request); AEAD failure (decrypt_failed); pt not canonical, no name, unknown keys, purpose over 200 or an unknown sensitivity (bad_request). ' +
      'invalid: open the wire with SealSK of open_with_epoch and MUST fail with expect_error. seal_invalid: sealWriteIntent MUST refuse target with expect_error.',
    origin: ORIGIN,
    cases: [
      create,
      ok('create_name_only', 'create', { name: 'Grüße API' }),
      ok('replace', 'replace', { name: 'OLD_TOKEN', purpose: 'Rotate after the incident' }),
      ok('create_epoch1', 'create', { name: 'A' }, 1),
    ],
    invalid: [
      bad('wrong_epoch_key', 'decrypt_failed', w, 2),
      bad('tampered_origin_account', 'decrypt_failed', { ...w, origin: { ...w.origin, account: 'acct_bob' } }),
      bad('tampered_origin_grant', 'decrypt_failed', { ...w, origin: { ...w.origin, grant_id: 'grant_other' } }),
      bad('tampered_operation', 'decrypt_failed', { ...w, operation: 'replace' }),
      bad('tampered_ts', 'decrypt_failed', { ...w, ts: w.ts + 1 }),
      bad('tampered_expires_at', 'decrypt_failed', { ...w, expires_at: w.expires_at + 1 }),
      bad('tampered_request_id', 'decrypt_failed', { ...w, request_id: id('write-intent/other') }),
      bad('tampered_key_epoch', 'decrypt_failed', { ...w, key_epoch: 2 }, 3),
      bad('tampered_ct', 'decrypt_failed', { ...w, ct: flipByte(w.ct, 3) }),
      bad('other_vault', 'bad_request', w, 3, VAULT_PERSONAL),
      bad('zero_epk', 'bad_request', { ...w, epk: b64(new Uint8Array(32)) }),
      bad('expires_not_after_ts', 'bad_request', { ...w, expires_at: w.ts }),
      bad('unknown_operation', 'bad_request', { ...w, operation: 'delete' }),
      bad('extra_target_key', 'bad_request', rawSeal(header, pt('{"name":"A","value":"v"}'), 'extra_target_key')),
      bad('missing_name', 'bad_request', rawSeal(header, pt('{"purpose":"x"}'), 'missing_name')),
      bad('empty_purpose', 'bad_request', rawSeal(header, pt('{"name":"A","purpose":""}'), 'empty_purpose')),
      bad('unknown_sensitivity', 'bad_request', rawSeal(header, pt('{"name":"A","sensitivity":"low"}'), 'unknown_sensitivity')),
      bad('non_canonical_pt', 'bad_request', rawSeal(header, pt('{"purpose":"x","name":"A"}'), 'non_canonical_pt')),
      bad('unknown_origin_kind', 'bad_request', { ...w, origin: { ...w.origin, kind: 'web' } }),
      bad('extra_wire_key', 'bad_request', { ...w, note: 'x' }),
      bad('unknown_alg', 'unsupported_version', { ...w, alg: 'x25519-aes-seal' }),
      bad('version_2', 'unsupported_version', { ...w, v: 2 }),
    ],
    seal_invalid: [
      sealBad('empty_name', 'bad_request', { name: '' }),
      sealBad('value_key', 'bad_request', { name: 'A', value: 'v' }),
      sealBad('purpose_too_long', 'bad_request', { name: 'A', purpose: 'p'.repeat(201) }),
    ],
  };
}

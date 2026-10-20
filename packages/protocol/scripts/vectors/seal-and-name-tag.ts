/** seal-key.json, sealed-op.json, name-tag.json */
import {
  buildSealKeyDoc,
  checkSealedDrain,
  checkSealKeyDocReplace,
  cjson,
  deriveSealKeyPair,
  kxKeyPairFromSecret,
  membershipEventHash,
  nameIndexKey,
  nameTag,
  openSealedOp,
  signSealKeyDoc,
  verifySealKeyDoc,
  x25519Shared,
  type SealedOperation,
  type SealedOpWire,
  type SealedOrigin,
} from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { concatBytes, utf8Encode } from '../../src/bytes.js';
import { hkdf32 } from '../../src/hkdf.js';
import { sealOpWithVectorValues } from '../../src/sealed-op.js';
import { aliceLaptop, alicePhone, b64, BASE_TS, bobLaptop, flipByte, id, key32, negative, nonce, seed, stranger, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';
import { sharedChain } from './membership.js';

/** Shared chain key epochs: 1 at seq 0..5, 2 at seq 6..7, 3 at seq 8 (membership.json chains[0]). */
const vk = (epoch: number) => key32(`vk/epoch${epoch}`);
const sealPair = (epoch: number) => deriveSealKeyPair(vk(epoch), VAULT_SHARED, epoch);
const tsAt = (seq: number) => BASE_TS + seq * 60_000 + 1_000;

export function sealKeyVectors(): Record<string, unknown> {
  const doc = (epoch: number, seq: number, author = alicePhone) =>
    buildSealKeyDoc({ vk: vk(epoch), vaultId: VAULT_SHARED, keyEpoch: epoch, membershipSeq: seq, author: author.record.device_id, ts: tsAt(seq) }, author.signSecret);
  const fields = (epoch: number, seq: number, author = alicePhone, sealPubEpoch = epoch) => ({
    vault_id: VAULT_SHARED, key_epoch: epoch, membership_seq: seq, seal_pub: b64(sealPair(sealPubEpoch).publicKey), author: author.record.device_id, ts: tsAt(seq),
  });
  // Optional chain pins: trusted_anchor and witnessed_checkpoint, as membership.json chains use them.
  type Pins = { trusted_anchor?: string; witnessed_checkpoint?: { membership_seq: number; membership_head: string } };
  const pinOpts = (p: Pins) => ({
    ...(p.trusted_anchor === undefined ? {} : { trustedAnchor: p.trusted_anchor }),
    ...(p.witnessed_checkpoint === undefined ? {} : { witnessedCheckpoint: p.witnessed_checkpoint }),
  });
  const ok = (name: string, d: unknown, epoch: number | null, pins: Pins = {}) => {
    verifySealKeyDoc(d, sharedChain, { vaultId: VAULT_SHARED, ...(epoch === null ? {} : { vk: vk(epoch) }), ...pinOpts(pins) });
    return { name, doc: d, vk: epoch === null ? null : b64(vk(epoch)), ...pins };
  };
  const bad = (name: string, code: string, d: unknown, epoch: number | null, vaultId = VAULT_SHARED, pins: Pins = {}) =>
    negative(name, code, { vault_id: vaultId, doc: d, vk: epoch === null ? null : b64(vk(epoch)), ...pins }, () =>
      verifySealKeyDoc(d, sharedChain, { vaultId, ...(epoch === null ? {} : { vk: vk(epoch) }), ...pinOpts(pins) }),
    );
  const anchor = alicePhone.record.sign_pub;
  const witnessed = { membership_seq: 7, membership_head: membershipEventHash(sharedChain[7]!) };
  const e1 = doc(1, 0);
  const e3 = doc(3, 8);
  const e1Later = doc(1, 4, aliceLaptop);
  const replaceCase = (name: string, stored: typeof e1 | null, incoming: typeof e1) => {
    checkSealKeyDocReplace(stored, incoming);
    return { name, stored, incoming };
  };
  return {
    version: 1,
    description:
      'Seal key and seal-key document (spec §3.6). seal_keys: SealSK[e] = HKDF-SHA256(ikm=VK[e], salt=b64decode(vault_id), info=utf8("akv1/seal-key\\n") || cjson({"key_epoch":e}), L=32), used unmodified as an X25519 secret; seal_pub = X25519(SealSK, 9). ' +
      'Documents are signed with context "akv1/seal-key" over the document without sig. verifySealKeyDoc(doc, chain, {vault_id, vk?, trusted_anchor?, witnessed_checkpoint?}) runs against membership.json chains[0] (the shared chain, verified in full) and checks in order: shape (exact keys; v = 1 else unsupported_version; IDs, 32-byte seal_pub, integers: bad_request); vault_id is the expected vault (bad_request); membership_seq <= verified head seq and key_epoch = the chain key epoch at membership_seq (bad_request); author is a human owner device current at membership_seq, never the recovery key (forbidden); signature under the author sign_pub (invalid_signature); with vk (null = not held), seal_pub = seal_pub recomputed from vk (forbidden). A case with trusted_anchor or witnessed_checkpoint verifies the chain with those pins as membership.json chains do (anchor mismatch: forbidden; a shorter or forked chain: rollback), and the prefix up to membership_seq with the anchor only. ' +
      'cases MUST verify; invalid MUST fail with expect_error. replace: the server keeps one document per (vault_id, key_epoch) and refuses an incoming document whose membership_seq is below the stored one (conflict); replace_cases MUST be accepted, replace_invalid MUST fail.',
    vault_id: VAULT_SHARED,
    chain: 'membership.json chains[0]',
    seal_keys: [1, 2, 3].map((epoch) => ({ key_epoch: epoch, vk: b64(vk(epoch)), seal_sk: b64(sealPair(epoch).secretKey), seal_pub: b64(sealPair(epoch).publicKey) })),
    other_vault_seal_pub: { vault_id: VAULT_PERSONAL, key_epoch: 1, vk: b64(vk(1)), seal_pub: b64(deriveSealKeyPair(vk(1), VAULT_PERSONAL, 1).publicKey) },
    cases: [
      ok('genesis_epoch1', e1, 1),
      ok('after_second_rekey_epoch3', e3, 3),
      ok('epoch2_without_vk', doc(2, 6), null),
      ok('epoch2_at_later_seq', doc(2, 7), 2),
      ok('owner_removed_later_signed_before_removal', e1Later, 1),
      ok('pinned_anchor_and_witnessed_checkpoint', e1, 1, { trusted_anchor: anchor, witnessed_checkpoint: witnessed }),
    ],
    invalid: [
      bad('seal_pub_does_not_match_vk', 'forbidden', signSealKeyDoc(fields(3, 8, alicePhone, 2), alicePhone.signSecret), 3),
      bad('editor_author', 'forbidden', signSealKeyDoc(fields(1, 1, bobLaptop), bobLaptop.signSecret), 1),
      bad('removed_owner_author', 'forbidden', signSealKeyDoc(fields(2, 6, aliceLaptop), aliceLaptop.signSecret), 2),
      bad('non_member_author', 'forbidden', signSealKeyDoc(fields(1, 0, stranger), stranger.signSecret), 1),
      bad('key_epoch_not_chain_epoch_at_seq', 'bad_request', signSealKeyDoc(fields(2, 5), alicePhone.signSecret), 2),
      bad('membership_seq_beyond_head', 'bad_request', signSealKeyDoc(fields(3, 9), alicePhone.signSecret), 3),
      bad('other_vault', 'bad_request', e1, 1, VAULT_PERSONAL),
      bad('tampered_ts', 'invalid_signature', { ...e1, ts: e1.ts + 1 }, 1),
      bad('signature_by_other_owner', 'invalid_signature', { ...e1, sig: signSealKeyDoc(fields(1, 0), aliceLaptop.signSecret).sig }, 1),
      bad('extra_key', 'bad_request', { ...e1, note: 'x' }, 1),
      bad('short_seal_pub', 'bad_request', { ...e1, seal_pub: b64(seed('short').slice(0, 31)) }, 1),
      bad('version_2', 'unsupported_version', { ...e1, v: 2 }, 1),
      bad('untrusted_anchor', 'forbidden', e1, 1, VAULT_SHARED, { trusted_anchor: stranger.record.sign_pub }),
      bad('chain_forks_from_witnessed_checkpoint', 'rollback', e1, 1, VAULT_SHARED, { witnessed_checkpoint: { membership_seq: 3, membership_head: b64(seed('seal-key/fork')) } }),
      bad('chain_behind_witnessed_checkpoint', 'rollback', e1, 1, VAULT_SHARED, { witnessed_checkpoint: { membership_seq: 9, membership_head: b64(seed('seal-key/ahead')) } }),
    ],
    replace_cases: [replaceCase('no_stored', null, e1), replaceCase('newer_seq_same_epoch', e1, e1Later), replaceCase('other_epoch', e3, e1)],
    replace_invalid: [negative('older_seq_same_epoch', 'conflict', { stored: e1Later, incoming: e1 }, () => checkSealKeyDocReplace(e1Later, e1))],
  };
}

const ORIGIN: SealedOrigin = { kind: 'mcp', account: 'acct_alice', client_id: 'mcp-client-example', grant_id: 'grant_example_1' };

/** Encrypt an arbitrary plaintext exactly as sealOp would (for negative vectors that sealOp refuses). */
function rawSeal(epoch: number, header: Omit<SealedOpWire, 'v' | 'alg' | 'epk' | 'n' | 'ct'>, plaintext: Uint8Array, label: string): SealedOpWire {
  const sealPub = sealPair(epoch).publicKey;
  const esk = seed(`sealed/esk/${label}`);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, sealPub), concatBytes(epk, sealPub), utf8Encode('akv1/seal'));
  const aad = { ctx: 'akv1/sealed-op', vault_id: header.vault_id, sealed_id: header.sealed_id, key_epoch: header.key_epoch, origin: header.origin, ts: header.ts };
  const n = nonce(`sealed/${label}`);
  return { v: 1, alg: 'x25519-xc20p-seal', ...header, epk: b64(epk), n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) } as SealedOpWire;
}

export function sealedOpVectors(): Record<string, unknown> {
  const seal = (label: string, op: SealedOperation, epoch = 3) =>
    sealOpWithVectorValues(
      sealPair(epoch).publicKey,
      { vaultId: VAULT_SHARED, keyEpoch: epoch, origin: ORIGIN, ts: BASE_TS + 3_600_000, op },
      { sealedId: id(`sealed/${label}`), ephemeralSecret: seed(`sealed/esk/${label}`), nonce: nonce(`sealed/${label}`) },
    );
  const ok = (name: string, op: SealedOperation, epoch = 3) => {
    const wire = seal(name, op, epoch);
    const opened = openSealedOp(sealPair(epoch).secretKey, wire, { vaultId: VAULT_SHARED });
    if (cjson(opened.op) !== cjson(op)) throw new Error(`sealed-op ${name}: round trip mismatch`);
    return { name, key_epoch: epoch, ephemeral_secret: b64(seed(`sealed/esk/${name}`)), op, plaintext: cjson(op), wire };
  };
  const bad = (name: string, code: string, wire: unknown, epoch = 3, vaultId = VAULT_SHARED) =>
    negative(name, code, { open_with_epoch: epoch, vault_id: vaultId, wire }, () => openSealedOp(sealPair(epoch).secretKey, wire, { vaultId }));
  const set = ok('set', { op: 'set', name: 'STRIPE_SECRET_KEY', value: 'sk_test_example_not_real', sensitivity: 'high' });
  const w = set.wire;
  const header = { sealed_id: w.sealed_id, vault_id: w.vault_id, key_epoch: w.key_epoch, origin: w.origin, ts: w.ts };
  const pt = (s: string) => utf8Encode(s);
  const zeroCt = b64(new Uint8Array(65_553));
  const { ct: _ct, ...wireWithoutCt } = w;
  const sealBad = (name: string, code: string, op: unknown) =>
    negative(name, code, { op }, () => seal(name, op as SealedOperation));
  // Drain admission for the opened `set` case, as the device of ORIGIN.account sees it.
  const TTL_S = 3600;
  const drainOpened = openSealedOp(sealPair(w.key_epoch).secretKey, w, { vaultId: w.vault_id });
  type Drain = { name: string; account?: string; now: number; seen?: string[] };
  const drainCase = (c: Drain) => {
    const ctx = { account: c.account ?? ORIGIN.account, now: c.now, sealed_ttl_s: TTL_S, seen: c.seen ?? [] };
    const run = () => checkSealedDrain(drainOpened, { account: ctx.account, now: ctx.now, sealedTtlS: TTL_S, seen: (sid) => ctx.seen.includes(sid) });
    return { name: c.name, ...ctx, run };
  };
  const drainOk = (c: Drain) => {
    const { run, ...rest } = drainCase(c);
    run();
    return rest;
  };
  const drainBad = (code: string, c: Drain) => {
    const { run, name, ...rest } = drainCase(c);
    return negative(name, code, rest, run);
  };
  const otherId = id('sealed/other');
  return {
    version: 1,
    description:
      'Sealed operations x25519-xc20p-seal (spec §3.6), sealed to seal_pub[e] of seal-key.json seal_keys (vault shared). ' +
      'epk = X25519(ephemeral_secret, 9); shared = X25519(ephemeral_secret, seal_pub) (all-zero: bad_request); seal_key = HKDF-SHA256(ikm=shared, salt=epk || seal_pub, info=utf8("akv1/seal"), L=32); aad = cjson({"ctx":"akv1/sealed-op","vault_id","sealed_id","key_epoch","origin","ts"}); ct = XChaCha20-Poly1305(seal_key, n, cjson(op), aad). ' +
      'cases: sealOp with the given ephemeral_secret, nonce wire.n and sealed_id MUST reproduce wire byte for byte, and openSealedOp(SealSK[key_epoch], wire, {vault_id}) MUST yield op. ' +
      'openSealedOp order: parse (v or alg unknown: unsupported_version; exact keys, IDs, epk 32 B, n 24 B, ct 16..65552 B, origin {kind "mcp", account 1..256, client_id 1..256 and grant_id 1..64 printable ASCII}, ts: bad_request); vault_id other than expected (bad_request); all-zero shared secret (bad_request); AEAD failure (decrypt_failed); pt not canonical, unknown op, set without value, delete with value or sensitivity, unknown keys (bad_request). ' +
      'invalid: open the wire with SealSK of open_with_epoch and MUST fail with expect_error; a wire with ct_zero_bytes replaces ct with b64 of that many zero bytes. seal_invalid: sealOp MUST refuse op with expect_error (an op with value_fill uses value = value_fill repeated value_length times). ' +
      'drain: opened = openSealedOp(SealSK[drain.wire.key_epoch], drain.wire, {vault_id: drain.wire.vault_id}); checkSealedDrain(opened, {account, now, sealed_ttl_s, seen}) takes only that authenticated result, in order: origin.account other than account (forbidden); sealed_id in seen, a replay (conflict); now - ts > sealed_ttl_s * 1000 (bad_request); ts - now > 300000 (bad_request). drain.cases MUST pass; drain.invalid MUST fail with expect_error.',
    origin: ORIGIN,
    cases: [set, ok('set_without_sensitivity', { op: 'set', name: 'Grüße API', value: '' }), ok('delete', { op: 'delete', name: 'OLD_TOKEN' }), ok('set_epoch1', { op: 'set', name: 'A', value: 'v1' }, 1)],
    invalid: [
      bad('wrong_epoch_key', 'decrypt_failed', w, 2),
      bad('tampered_origin_account', 'decrypt_failed', { ...w, origin: { ...w.origin, account: 'acct_bob' } }),
      bad('tampered_origin_client_id', 'decrypt_failed', { ...w, origin: { ...w.origin, client_id: 'other-client' } }),
      bad('tampered_ts', 'decrypt_failed', { ...w, ts: w.ts + 1 }),
      bad('tampered_sealed_id', 'decrypt_failed', { ...w, sealed_id: id('sealed/other') }),
      bad('tampered_key_epoch', 'decrypt_failed', { ...w, key_epoch: 2 }, 3),
      bad('tampered_ct', 'decrypt_failed', { ...w, ct: flipByte(w.ct, 3) }),
      bad('other_vault', 'bad_request', w, 3, VAULT_PERSONAL),
      bad('zero_epk', 'bad_request', { ...w, epk: b64(new Uint8Array(32)) }),
      bad('delete_with_value', 'bad_request', rawSeal(3, header, pt('{"name":"OLD_TOKEN","op":"delete","value":"x"}'), 'delete_with_value')),
      bad('delete_with_sensitivity', 'bad_request', rawSeal(3, header, pt('{"name":"OLD_TOKEN","op":"delete","sensitivity":"high"}'), 'delete_with_sensitivity')),
      bad('set_without_value', 'bad_request', rawSeal(3, header, pt('{"name":"A","op":"set"}'), 'set_without_value')),
      bad('unknown_op', 'bad_request', rawSeal(3, header, pt('{"name":"A","op":"rename"}'), 'unknown_op')),
      bad('extra_pt_key', 'bad_request', rawSeal(3, header, pt('{"name":"A","op":"set","value":"v","x":1}'), 'extra_pt_key')),
      bad('non_canonical_pt', 'bad_request', rawSeal(3, header, pt('{"op":"set","name":"A","value":"v"}'), 'non_canonical_pt')),
      negative('oversize_ct', 'bad_request', { open_with_epoch: 3, vault_id: VAULT_SHARED, wire: wireWithoutCt, ct_zero_bytes: 65_553 }, () => openSealedOp(sealPair(3).secretKey, { ...w, ct: zeroCt }, { vaultId: VAULT_SHARED })),
      bad('unknown_origin_kind', 'bad_request', { ...w, origin: { ...w.origin, kind: 'web' } }),
      bad('non_ascii_client_id', 'bad_request', { ...w, origin: { ...w.origin, client_id: 'clïent' } }),
      bad('extra_wire_key', 'bad_request', { ...w, note: 'x' }),
      bad('unknown_alg', 'unsupported_version', { ...w, alg: 'x25519-aes-seal' }),
      bad('version_2', 'unsupported_version', { ...w, v: 2 }),
    ],
    seal_invalid: [
      sealBad('delete_with_value', 'bad_request', { op: 'delete', name: 'A', value: 'x' }),
      negative('oversize_pt', 'bad_request', { op: { op: 'set', name: 'A' }, value_fill: 'a', value_length: 65_536 }, () => seal('oversize_pt', { op: 'set', name: 'A', value: 'a'.repeat(65_536) })),
      sealBad('empty_name', 'bad_request', { op: 'set', name: '', value: 'v' }),
    ],
    drain: {
      wire: w,
      cases: [
        drainOk({ name: 'fresh', now: w.ts }),
        drainOk({ name: 'other_id_seen', now: w.ts, seen: [otherId] }),
        drainOk({ name: 'at_ttl', now: w.ts + TTL_S * 1000 }),
        drainOk({ name: 'future_at_limit', now: w.ts - 300_000 }),
      ],
      invalid: [
        drainBad('conflict', { name: 'replay', now: w.ts + 1000, seen: [otherId, w.sealed_id] }),
        drainBad('conflict', { name: 'replay_after_ttl', now: w.ts + TTL_S * 1000 + 1, seen: [w.sealed_id] }),
        drainBad('forbidden', { name: 'other_account', account: 'acct_bob', now: w.ts }),
        drainBad('forbidden', { name: 'other_account_replay', account: 'acct_bob', now: w.ts, seen: [w.sealed_id] }),
        drainBad('bad_request', { name: 'expired', now: w.ts + TTL_S * 1000 + 1 }),
        drainBad('bad_request', { name: 'too_far_future', now: w.ts - 300_001 }),
      ],
    },
  };
}

export function nameTagVectors(): Record<string, unknown> {
  const key = (epoch: number, vaultId = VAULT_SHARED) => nameIndexKey(vk(epoch), vaultId, epoch);
  const tag = (name: string, epoch = 3, vaultId = VAULT_SHARED) => ({ name, key_epoch: epoch, vault_id: vaultId, tag: nameTag(key(epoch, vaultId), name) });
  const nfc = 'Caf\u00e9 API';
  const nfd = 'Cafe\u0301 API';
  const same = [tag(nfc), tag(nfd)];
  const differ = [tag('GITHUB_TOKEN', 3), tag('GITHUB_TOKEN', 2), tag('GITHUB_TOKEN', 3, VAULT_PERSONAL)];
  if (same[0]!.tag !== same[1]!.tag) throw new Error('name-tag: NFC and NFD differ');
  if (new Set(differ.map((d) => d.tag)).size !== 3) throw new Error('name-tag: epoch or vault tags collide');
  return {
    version: 1,
    description:
      'Name tags (spec §3.7). NameIndexKey[e] = HKDF-SHA256(ikm=VK[e], salt=b64decode(vault_id), info=utf8("akv1/name-index\\n") || cjson({"key_epoch":e}), L=32); name_tag = b64(HKDF-SHA256(ikm=NameIndexKey[e], salt="" (HashLen zero bytes), info=utf8("akv1/name-tag\\n") || utf8(NFC(name)), L=16)). VK[e] is seal-key.json seal_keys[e].vk (used for both vaults here). ' +
      'index_keys and every tag MUST reproduce. same_tag: all entries give one tag (NFC and NFD spellings). distinct_tags: pairwise different (another epoch, another vault). known_answers: ASCII and non-ASCII names. A name is 1..4096 UTF-16 code units and well formed; invalid names MUST fail with expect_error.',
    index_keys: [
      { vault_id: VAULT_SHARED, key_epoch: 2, vk: b64(vk(2)), index_key: b64(key(2)) },
      { vault_id: VAULT_SHARED, key_epoch: 3, vk: b64(vk(3)), index_key: b64(key(3)) },
      { vault_id: VAULT_PERSONAL, key_epoch: 3, vk: b64(vk(3)), index_key: b64(key(3, VAULT_PERSONAL)) },
    ],
    same_tag: same,
    distinct_tags: differ,
    known_answers: [tag('OPENAI_API_KEY'), tag('stripe live key'), tag('東京 データベース'), tag('🔑 deploy')],
    invalid: [
      negative('empty_name', 'bad_request', { key_epoch: 3, vault_id: VAULT_SHARED, name: '' }, () => nameTag(key(3), '')),
      negative('lone_surrogate', 'bad_request', { key_epoch: 3, vault_id: VAULT_SHARED, name_utf16_hex: 'd800' }, () => nameTag(key(3), '\ud800')),
    ],
  };
}

/**
 * Seeded traffic for the platform log disclosure scan. Two devices enroll, push,
 * pull and checkpoint; the owner writes audit entries and a recovery bundle; a
 * third device recovers from the recovery kit, removes a lost device, rekeys and
 * rotates the recovery key; a session is revoked by webhook. Then the error
 * paths: bad, expired and foreign tokens, bad, foreign and replayed proofs, a
 * revoked session, refused and oversize bodies, a reused idempotency key, bad
 * webhook calls and canaries in URLs and headers.
 *
 * Every planted value goes into the NeedleSet under its category. Each step
 * checks its expected status, so a run that did not reach a code path fails
 * instead of reporting a clean scan of traffic that never happened.
 */
import {
  appendAuditEntry,
  b64encode,
  deriveAuditKey,
  encodeRecoveryKey,
  generateRecoveryKey,
  openRecoveryBundle,
  randomBytes,
  randomId,
  sealRecoveryBundle,
  signCheckpoint,
  signKeyPairFromSeed,
  utf8Encode,
  verifyMembershipChain,
  type JsonObject,
  type MembershipEvent,
} from '@ak-vault/protocol';
import { LIMITS } from '../../src/limits.js';
import { canary, labDevice, webhookSignature, type CallResult, type LabClient } from './lab-client.js';
import { LabVault, signerOf, type PulledItem } from './lab-vault-model.js';
import type { NeedleSet } from './needle-scan.js';

export interface StepResult {
  step: string;
  expected: number;
  got: number;
}

const ARGON_TEST_PARAMS = { t: 2, m: 19_456, p: 1 };

export async function runLabTraffic(client: LabClient, needles: NeedleSet, webhookSecret: string): Promise<{ steps: StepResult[]; vaultIds: string[] }> {
  const steps: StepResult[] = [];
  const expect = (step: string, res: CallResult, expected: number): CallResult => {
    steps.push({ step, expected, got: res.status });
    return res;
  };

  expect('healthz', await client.raw('/healthz', { method: 'GET' }), 200);
  expect('meta', await client.raw('/v1/meta', { method: 'GET' }), 200);

  // Two devices of one synthetic account.
  const account = `acct-logscan-${randomId()}`;
  const owner = labDevice('owner', account, needles);
  const laptop = labDevice('laptop', account, needles);
  const vault = new LabVault(client, needles, owner);
  expect('genesis', await vault.genesis(), 201);
  const enroll = vault.enrollEvent(laptop);
  expect('enroll laptop (device_add with wrap)', await vault.append(owner, enroll.event, enroll.wraps), 201);
  const laptopWrap = await vault.receiveWrap(laptop, vault.state.seq);
  expect('laptop fetches and unwraps its key', laptopWrap.res, 200);
  if (!laptopWrap.vk || b64encode(laptopWrap.vk) !== b64encode(vault.vk.get(1)!)) throw new Error('laptop unwrapped a different vault key');

  // Push: canary secret names and values, as a client stores them (inside item ciphertext).
  const plant = (): PulledItem => {
    const item = { name: `LOGSCAN_NAME_${randomId().replaceAll('-', '_')}`, value: canary('logscan-value') };
    needles.add('secret_names', item.name);
    needles.add('secret_values', item.value);
    return item;
  };
  const items = [randomId(), randomId(), randomId(), randomId()];
  const planted = new Map<string, PulledItem>();
  for (const id of items) {
    const value = plant();
    planted.set(id, value);
    expect('owner pushes a secret', await vault.write(owner, id, 0, value), 200);
  }

  // Pull on the other device, verify and decrypt, then both devices checkpoint.
  const pulled = await vault.pull(laptop);
  for (const [id, value] of planted) if (pulled.items.get(id)?.value !== value.value) throw new Error('laptop pull did not return the pushed secret');
  expect('laptop checkpoint', await vault.checkpoint(laptop, pulled), 201);
  expect('owner checkpoint', await vault.checkpoint(owner, await vault.pull(owner)), 201);

  // CAS: an edit, a preserved conflict, a delete and a refused resurrection.
  const [first, second] = items as [string, string];
  expect('laptop edits', await vault.write(laptop, first, 1, plant()), 200);
  expect('owner stale edit is a preserved conflict', await vault.write(owner, first, 1, plant()), 409);
  expect('owner deletes', await vault.write(owner, second, 1, null), 200);
  expect('laptop stale edit below the tombstone', await vault.write(laptop, second, 1, plant()), 409);
  expect('laptop pull after conflict and delete', (await vault.call(laptop, 'GET', '/changes?cursor=0')), 200);

  // Encrypted audit stream.
  const auditNote = canary('logscan-audit');
  const auditName = `LOGSCAN_AUDIT_NAME_${randomId().replaceAll('-', '_')}`;
  needles.add('secret_values', auditNote);
  needles.add('secret_names', auditName);
  needles.add('keys', deriveAuditKey(vault.vk.get(1)!, vault.vaultId, 1));
  const audit = appendAuditEntry({ vk: vault.vk.get(1)!, vaultId: vault.vaultId, keyEpoch: 1, head: null, event: { op: 'item.reveal', name: auditName, note: auditNote } });
  expect('owner appends audit', await vault.call(owner, 'POST', '/audit', { start_seq: 0, prev: '', entries: [audit.entry as unknown as JsonObject] }), 201);

  // Recovery kit: password and recovery key seal the bundle.
  const sealBundle = (seq: number, recoverySk: Uint8Array) => {
    const password = canary('logscan-recovery-password');
    const rk = generateRecoveryKey();
    needles.add('recovery_material', password, rk, encodeRecoveryKey(rk));
    const at = vault.state;
    const checkpoint = signCheckpoint(
      { vault_id: vault.vaultId, membership_seq: at.seq, membership_head: at.head, log_seq: pulled.cursor.log_seq, state_digest: pulled.stateDigest, key_epoch: vault.keyEpoch, ts: Date.now(), author: owner.keys.record.device_id },
      owner.keys.signSecret,
    );
    const vk = Object.fromEntries([...vault.vk].map(([e, k]) => [String(e), k]));
    return { rk, bundle: sealRecoveryBundle({ vaultId: vault.vaultId, bundleSeq: seq, vk, ownerSignPub: owner.keys.record.sign_pub, recoverySignSk: recoverySk, checkpoint, password, rk, params: ARGON_TEST_PARAMS }) };
  };
  const kit = sealBundle(1, vault.recovery.secretKey);
  expect('owner uploads the recovery bundle', await vault.call(owner, 'PUT', '/recovery', { bundle: kit.bundle as unknown as JsonObject, membership_seq: vault.state.seq }), 200);

  // Recovery: a fresh device of the owner account, with only the recovery kit.
  const fresh = labDevice('recovered', account, needles);
  const keyHeader = { headers: { 'AKV-Device-Key': fresh.keys.record.sign_pub } };
  const chainRes = expect('recovering device reads membership', await vault.call(fresh, 'GET', '/membership', undefined, keyHeader), 200);
  const chain = verifyMembershipChain(chainRes.json.events as MembershipEvent[], { trustedAnchor: owner.keys.record.sign_pub, vaultId: vault.vaultId });
  const bundleRes = expect('recovering device fetches the bundle', await vault.call(fresh, 'GET', '/recovery', undefined, keyHeader), 200);
  const opened = openRecoveryBundle({ bundle: bundleRes.json.bundle, vaultId: vault.vaultId, rk: kit.rk, recoverySignPub: chain.recovery_sign_pub });
  const recoveryEnroll = vault.enrollEvent(fresh, { id: chain.recovery_author, secret: opened.recovery_sign_sk });
  expect('recovery enrolls the new device', await vault.append(fresh, recoveryEnroll.event, recoveryEnroll.wraps), 201);
  expect('recovered device unwraps its key', (await vault.receiveWrap(fresh, vault.state.seq)).res, 200);

  // Removal of the lost laptop by the recovered device, then rekey.
  expect('recovered device removes the laptop', await vault.removeDevice(fresh, laptop), 201);
  expect('recovered device rekeys', await vault.rekey(fresh), 201);
  expect('removed laptop cannot write', await vault.write(laptop, randomId(), 0, plant()), 403);
  expect('removed laptop cannot read', await vault.call(laptop, 'GET', '/changes?cursor=0'), 403);
  expect('recovered device pushes', await vault.write(fresh, randomId(), 0, plant()), 200);
  await vault.pull(owner);

  // Recovery key rotation, with a resealed bundle.
  const rotated = signKeyPairFromSeed(randomBytes(32));
  needles.add('recovery_material', rotated.secretKey);
  const rotateKit = sealBundle(2, rotated.secretKey);
  const rotate = vault.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) });
  expect('owner rotates the recovery key', await vault.append(owner, rotate, undefined, { bundle: rotateKit.bundle as unknown as JsonObject }), 201);

  // Revocation webhook: revoke the owner's session; its next request is refused.
  const webhook = async (body: Uint8Array, signature?: string) => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = signature ?? (await webhookSignature(webhookSecret, ts, body));
    needles.add('webhook_material', sig);
    return client.raw('/internal/v1/revocations', { method: 'POST', body, headers: { 'Content-Type': 'application/json', 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': sig } });
  };
  const revokeBody = utf8Encode(JSON.stringify({ v: 1, event_id: randomId(), revoke_sids: [owner.sid], revoke_dids: [laptop.keys.record.device_id], min_iat: [] }));
  expect('webhook revokes the owner session', await webhook(revokeBody), 200);
  expect('revoked session is refused', await vault.call(owner, 'GET', '/changes?cursor=0'), 401);
  owner.sid = `sid-${randomId()}`;
  expect('owner signs in again', await vault.call(owner, 'GET', '/changes?cursor=0'), 200);

  // Error paths. Tokens.
  const badBearer = canary('logscan-bad-bearer');
  needles.add('tokens', badBearer);
  expect('garbage bearer token', await vault.call(owner, 'GET', '/changes', undefined, { token: badBearer }), 401);
  const claimCanary = canary('logscan-token-claim');
  needles.add('tokens', claimCanary);
  const foreignAud = await client.issuer.mint(owner, { claims: { aud: 'https://other.invalid', note: claimCanary } });
  expect('token for another audience', await vault.call(owner, 'GET', '/changes', undefined, { token: foreignAud }), 401);
  const now = Math.floor(Date.now() / 1000);
  const expired = await client.issuer.mint(owner, { claims: { iat: now - 900, nbf: now - 900, exp: now - 600 } });
  expect('expired token', await vault.call(owner, 'GET', '/changes', undefined, { token: expired }), 401);
  expect('no token', await vault.call(owner, 'GET', '/changes', undefined, { token: null, proof: null }), 401);

  // Proofs.
  const badProof = canary('logscan-bad-proof');
  needles.add('proofs', badProof);
  expect('garbage proof', await vault.call(owner, 'GET', '/changes', undefined, { proof: badProof }), 401);
  const thief = randomBytes(32);
  needles.add('keys', thief);
  expect('stolen token with a foreign proof key', await vault.call(owner, 'GET', '/changes', undefined, { proofSecret: thief }), 401);
  const once = expect('fresh request', await vault.call(owner, 'GET', '/changes?cursor=0'), 200);
  expect('replayed proof', await vault.call(owner, 'GET', '/changes?cursor=0', undefined, { token: once.token, proof: once.proof }), 401);
  const headerCanary = canary('logscan-device-key-header');
  needles.add('request_header_canaries', headerCanary);
  expect('malformed device-key header on the recovery path', await vault.call(labDevice('stranger', account, needles), 'GET', '/recovery', undefined, { headers: { 'AKV-Device-Key': headerCanary } }), 401);

  // Bodies.
  const bodyCanary = canary('logscan-body');
  needles.add('request_body_canaries', bodyCanary);
  expect('malformed JSON body', await vault.call(owner, 'PUT', `/items/${randomId()}`, undefined, { rawBody: utf8Encode(`{"${bodyCanary}":`) }), 400);
  expect('malformed checkpoint', await vault.call(owner, 'POST', '/checkpoints', { checkpoint: { note: bodyCanary } }), 400);
  expect('malformed membership event', await vault.call(owner, 'POST', '/membership', { event: { type: bodyCanary, body: { name: bodyCanary } } }), 400);
  const oversize = utf8Encode(JSON.stringify({ pad: bodyCanary.repeat(Math.ceil(LIMITS.request_body_max_bytes / bodyCanary.length) + 1) }));
  expect('oversize body', await vault.call(owner, 'PUT', `/items/${randomId()}`, undefined, { rawBody: oversize }), 413);
  const reused = `idem-${randomId()}`;
  needles.add('idempotency_keys', reused);
  const reusedItem = randomId();
  expect('write with an idempotency key', await vault.write(owner, reusedItem, 0, plant(), { idempotencyKey: reused }), 200);
  expect('same idempotency key, other body', await vault.write(owner, reusedItem, 0, plant(), { idempotencyKey: reused }), 422);

  // Webhook refusals.
  const webhookCanary = canary('logscan-webhook');
  needles.add('webhook_material', webhookCanary);
  expect('webhook with a bad signature', await webhook(utf8Encode(JSON.stringify({ v: 1, event_id: webhookCanary })), canary('logscan-webhook-sig')), 401);
  expect('signed but malformed webhook body', await webhook(utf8Encode(JSON.stringify({ v: 1, event_id: randomId(), revoke_sids: [], revoke_dids: [], min_iat: [], [webhookCanary]: 1 }))), 400);

  // URLs: canaries a buggy or hostile client puts in the query string or path.
  const urlCanary = canary('logscan-url');
  needles.add('url_canaries', urlCanary);
  expect('canary in a query string', await vault.call(owner, 'GET', `/changes?cursor=${urlCanary}`), 400);
  expect('canary as a vault id', await client.call(owner, 'GET', `/v1/vaults/${urlCanary}/changes`), 400);
  expect('canary in an unknown route', await client.call(owner, 'GET', `/v1/${urlCanary}`), 404);

  return { steps, vaultIds: [vault.vaultId] };
}

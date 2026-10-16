/**
 * Red-team disclosure scan over the request surfaces an attacker or a buggy
 * client controls: query strings, path segments, headers (proof, idempotency
 * key, device key, bearer), unknown routes, webhook bodies and refused writes.
 * Each carries a synthetic canary; afterwards every response body and header,
 * every console line and both Durable Object dumps must contain none of them.
 * Complements disclosure-scan.test.ts, which plants canaries in the encrypted
 * channels (item names and values, audit, recovery secrets) on success paths.
 */
import { env } from 'cloudflare:workers';
import { randomId, utf8Encode } from '@ak-vault/protocol';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { LIMITS } from '../src/limits.js';
import { call, createDevice, fetchRaw, type CallResult } from './helpers/api-client.js';
import { dumpDurableObject, findLeak } from './helpers/disclosure-scan.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { hmac } from './helpers/webhook.js';

// All synthetic; URL- and header-safe so each reaches the code path it targets.
const CANARY_NAME = `CANARY_NAME_${randomId()}`;
const CANARY_VALUE = `canary-value-${randomId()}`;
const CANARY_QUERY = `canary-query-${randomId()}`;
const CANARY_PATH = `canary-path-${randomId()}`;
const CANARY_IDEM = `canary-idem-${randomId()}`;
const CANARY_PROOF = `canary-proof-${randomId()}`;
const CANARY_DEVICE_KEY = `canary-device-key-${randomId()}`;
const CANARY_BEARER = `canary-bearer-${randomId()}`;
const CANARY_WEBHOOK = `canary-webhook-${randomId()}`;
const CANARY_BODY = `canary-body-${randomId()}`;
const CANARIES = [CANARY_NAME, CANARY_VALUE, CANARY_QUERY, CANARY_PATH, CANARY_IDEM, CANARY_PROOF, CANARY_DEVICE_KEY, CANARY_BEARER, CANARY_WEBHOOK, CANARY_BODY];

let spies: MockInstance[] = [];
const logged = () => spies.flatMap((s) => s.mock.calls.map((args) => args.map(String).join(' '))).join('\n');

beforeEach(() => {
  spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m));
});
afterEach(() => {
  for (const s of spies) s.mockRestore();
});

interface Seen {
  status: number;
  text: string;
}

const fromCall = (r: CallResult): Seen => ({ status: r.status, text: `${JSON.stringify(r.json)}\n${[...r.headers].map(([k, v]) => `${k}: ${v}`).join('\n')}` });

async function fromResponse(r: Response): Promise<Seen> {
  return { status: r.status, text: `${await r.text()}\n${[...r.headers].map(([k, v]) => `${k}: ${v}`).join('\n')}` };
}

describe('red team: planted plaintext in attacker-controlled request surfaces', () => {
  it('no canary from a query, path, header, webhook or refused body reaches a response, log or dump', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const vaultPath = `/v1/vaults/${fx.vaultId}`;
    const seen: Seen[] = [];

    // Accepted write carrying a canary name and value, then refused variants of it.
    const itemId = randomId();
    seen.push(fromCall(await fx.write(fx.owner, itemId, 0, { name: CANARY_NAME, value: CANARY_VALUE })));
    seen.push(fromCall(await fx.write(laptop, itemId, 0, { name: CANARY_NAME, value: `${CANARY_VALUE}-conflict` }))); // 409 preserved branch
    seen.push(fromCall(await fx.write(fx.owner, itemId, 1, null))); // tombstone
    seen.push(fromCall(await fx.write(laptop, itemId, 1, { name: CANARY_NAME, value: CANARY_VALUE }))); // 409 below tombstone

    // Query string, path segment, unknown route.
    seen.push(fromCall(await fx.get(fx.owner, `/changes?cursor=${CANARY_QUERY}`)));
    seen.push(fromCall(await fx.get(fx.owner, `/changes?limit=${CANARY_QUERY}&${CANARY_QUERY}=1`)));
    seen.push(fromCall(await fx.get(fx.owner, `/items/${CANARY_PATH}`)));
    seen.push(fromCall(await call(fx.owner, 'GET', `/v1/vaults/${CANARY_PATH}/changes`)));
    seen.push(fromCall(await call(fx.owner, 'GET', `${vaultPath}/${CANARY_PATH}`)));
    seen.push(fromCall(await call(fx.owner, 'GET', `/v1/${CANARY_PATH}`)));

    // Headers: idempotency key reused with another body, garbage proof, device key, bearer.
    const reused = randomId();
    seen.push(fromCall(await fx.write(fx.owner, reused, 0, { name: CANARY_NAME, value: 'a' }, { idempotencyKey: CANARY_IDEM })));
    seen.push(fromCall(await fx.write(fx.owner, reused, 0, { name: CANARY_NAME, value: 'b' }, { idempotencyKey: CANARY_IDEM }))); // 422
    seen.push(fromCall(await fx.get(fx.owner, '/changes', { proof: CANARY_PROOF })));
    // The device-key header is parsed only on the recovery-identity path: a fresh, not-enrolled device of the owner account.
    seen.push(fromCall(await fx.get(createDevice(fx.owner.account), '/recovery', { headers: { 'AKV-Device-Key': CANARY_DEVICE_KEY } })));
    seen.push(fromCall(await fx.get(fx.owner, '/changes', { token: CANARY_BEARER })));

    // Refused bodies: malformed JSON, wrong shapes, oversize.
    seen.push(fromCall(await call(fx.owner, 'PUT', `${vaultPath}/items/${randomId()}`, undefined, { rawBody: utf8Encode(`{"${CANARY_BODY}":`) })));
    seen.push(fromCall(await fx.post(fx.owner, '/checkpoints', { checkpoint: { note: CANARY_BODY } })));
    seen.push(fromCall(await fx.post(fx.owner, '/membership', { event: { type: CANARY_BODY, body: { name: CANARY_NAME } } })));
    seen.push(fromCall(await fx.post(fx.owner, '/audit', { start_seq: 0, prev: CANARY_BODY, entries: [{ ct: CANARY_VALUE }] })));
    const oversize = utf8Encode(JSON.stringify({ pad: CANARY_BODY.repeat(Math.ceil(LIMITS.request_body_max_bytes / CANARY_BODY.length) + 1) }));
    seen.push(fromCall(await call(fx.owner, 'PUT', `${vaultPath}/items/${randomId()}`, undefined, { rawBody: oversize })));

    // Revocation webhook: bad HMAC, then a correctly signed but malformed body.
    const webhook = async (bytes: Uint8Array, signature?: string) => {
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = signature ?? (await hmac(env.REVOCATION_WEBHOOK_SECRET!, ts, bytes));
      return fromResponse(await fetchRaw('/internal/v1/revocations', { method: 'POST', body: bytes, headers: { 'Content-Type': 'application/json', 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': sig } }));
    };
    seen.push(await webhook(utf8Encode(JSON.stringify({ v: 1, event_id: CANARY_WEBHOOK })), CANARY_WEBHOOK));
    seen.push(await webhook(utf8Encode(JSON.stringify({ v: 1, event_id: randomId(), revoke_sids: [], revoke_dids: [], min_iat: [], [CANARY_WEBHOOK]: CANARY_NAME }))));
    seen.push(await webhook(utf8Encode(`{"v":1,"event_id":"${CANARY_WEBHOOK}`)));

    expect(seen.map((s) => s.status)).toEqual([200, 409, 200, 409, 400, 400, 400, 400, 404, 404, 200, 422, 401, 401, 401, 400, 400, 400, 400, 413, 401, 400, 400]);

    const responses = seen.map((s) => s.text).join('\n');
    // The accepted write's own name and value are inside ciphertext only, so no response may carry them either.
    expect(findLeak(responses, CANARIES)).toBeNull();

    const logs = logged();
    expect(logs).toContain('"route"');
    expect(findLeak(logs, [...CANARIES, fx.vaultId, itemId, reused])).toBeNull();

    const vault = await dumpDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)));
    const registry = await dumpDurableObject(env.REVOCATIONS.get(env.REVOCATIONS.idFromName('global')));
    expect(vault.tables).toEqual(expect.arrayContaining(['records', 'idempotency', 'proof_seen']));
    expect(findLeak(`${vault.text}\n${registry.text}`, CANARIES)).toBeNull();
    // Nothing was created under a malformed or canary vault path.
    const stray = await dumpDurableObject(env.VAULT.get(env.VAULT.idFromName(CANARY_PATH)));
    expect(stray.text).toBe('');
  });
});

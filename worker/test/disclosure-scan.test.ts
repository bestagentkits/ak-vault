/**
 * Plants canary plaintext in every client-side secret channel (item names and
 * values, audit events, recovery password and keys), then scans everything the
 * server keeps or emits: every Durable Object table, every console line and the
 * response bodies. Also checks bearer tokens and proofs are never persisted or
 * logged, and that an internal failure fails closed without echoing details.
 */
import { env } from 'cloudflare:workers';
import { appendAuditEntry, deriveAuditKey, generateRecoveryKey, randomBytes, randomId, sealRecoveryBundle, sha256b64, signCheckpoint, type JsonObject } from '@ak-vault/protocol';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import type { Env } from '../src/env.js';
import { call, fetchRaw, type CallResult } from './helpers/api-client.js';
import { dumpDurableObject, encodings, findLeak } from './helpers/disclosure-scan.js';
import { putTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const CANARY_NAME = `CANARY_NAME_${randomId()}`;
const CANARY_VALUE = `canary-value-${randomId()}-do-not-store`;
const CANARY_AUDIT = `canary-audit-${randomId()}`;
const CANARY_PASSWORD = `canary-password-${randomId()}`;

let spies: MockInstance[] = [];
const logged = () => spies.flatMap((s) => s.mock.calls.map((args) => args.map(String).join(' '))).join('\n');

beforeEach(() => {
  spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m));
});
afterEach(() => {
  for (const s of spies) s.mockRestore();
});

describe('disclosure scan', () => {
  it('encodings() finds a canary embedded at any alignment', () => {
    const secret = randomBytes(20);
    for (let k = 0; k < 3; k++) {
      const buf = new Uint8Array(k + 20 + 2);
      buf.set(secret, k);
      let s = '';
      for (const b of buf) s += String.fromCharCode(b);
      expect(findLeak(`x ${btoa(s)} y`, [secret])).not.toBeNull();
    }
    expect(encodings('abc')).toContain('616263');
  });

  it('no canary, vault key, recovery secret, token or proof is stored or logged', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const responses: CallResult[] = [];
    const itemId = randomId();
    responses.push(await fx.write(fx.owner, itemId, 0, { name: CANARY_NAME, value: CANARY_VALUE }));
    responses.push(await fx.write(laptop, itemId, 0, { name: CANARY_NAME, value: `${CANARY_VALUE}-branch` }));
    responses.push(await fx.write(fx.owner, itemId, 1, null));
    responses.push(await fx.write(laptop, itemId, 1, { name: CANARY_NAME, value: CANARY_VALUE }));

    const audit = appendAuditEntry({ vk: fx.vk.get(1)!, vaultId: fx.vaultId, keyEpoch: 1, head: null, event: { op: 'item.reveal', name: CANARY_NAME, note: CANARY_AUDIT } });
    responses.push(await fx.post(fx.owner, '/audit', { start_seq: 0, prev: '', entries: [audit.entry as unknown as JsonObject] }));

    const rk = generateRecoveryKey();
    const checkpoint = signCheckpoint(
      { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(new Uint8Array(1)), key_epoch: 1, ts: Date.now(), author: fx.owner.keys.record.device_id },
      fx.owner.keys.signSecret,
    );
    const bundle = sealRecoveryBundle({ vaultId: fx.vaultId, bundleSeq: 1, vk: { '1': fx.vk.get(1)! }, ownerSignPub: fx.owner.keys.record.sign_pub, recoverySignSk: fx.recovery.secretKey, checkpoint, password: CANARY_PASSWORD, rk, params: { t: 2, m: 19_456, p: 1 } });
    responses.push(await putTestBundle(fx, fx.owner, bundle));
    responses.push(await fx.get(laptop, '/changes'));
    // Error paths with secrets in the request must not echo them back.
    responses.push(await fx.post(fx.owner, '/audit', { start_seq: 0, prev: CANARY_VALUE, entries: [] }));
    responses.push(await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/items/${randomId()}`, undefined, { rawBody: new TextEncoder().encode(`{"name":"${CANARY_NAME}"`) }));
    responses.push(await call(null, 'GET', `/v1/vaults/${fx.vaultId}/changes`, undefined, { token: `${CANARY_VALUE}.x.y` }));
    expect(responses.map((r) => r.status)).toEqual([200, 409, 200, 409, 201, 200, 200, 400, 400, 401]);

    const secrets: (string | Uint8Array)[] = [CANARY_NAME, CANARY_VALUE, CANARY_AUDIT, CANARY_PASSWORD, fx.vk.get(1)!, deriveAuditKey(fx.vk.get(1)!, fx.vaultId, 1), rk, fx.recovery.secretKey, fx.owner.keys.signSecret];
    const credentials = responses.flatMap((r) => [r.token, r.proof]).filter((x): x is string => typeof x === 'string');
    expect(credentials.length).toBeGreaterThan(10);

    const vault = await dumpDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)));
    expect(vault.tables).toEqual(expect.arrayContaining(['records', 'audit_entries', 'recovery_blob', 'idempotency', 'proof_seen']));
    expect(vault.text.length).toBeGreaterThan(1000);
    const registry = await dumpDurableObject(env.REVOCATIONS.get(env.REVOCATIONS.idFromName('global')));
    const stored = `${vault.text}\n${registry.text}`;
    expect(findLeak(stored, secrets)).toBeNull();
    // Whole tokens/proofs and their signature segments (the part that makes them usable).
    const credentialParts = credentials.flatMap((c) => [c, ...c.split('.').filter((p) => p.length >= 32)]);
    for (const part of credentialParts) expect(stored.includes(part)).toBe(false);

    const logs = logged();
    expect(logs).toContain('"route"');
    expect(findLeak(logs, [...secrets, ...credentials, fx.vaultId, fx.owner.keys.record.device_id, itemId])).toBeNull();
    expect(findLeak(JSON.stringify(responses.slice(7).map((r) => r.json)), [CANARY_NAME, CANARY_VALUE])).toBeNull();
  });

  it('an internal failure fails closed with a generic body and no detail in logs', async () => {
    const fx = await VaultFixture.create();
    const failing = {
      idFromName: (n: string) => env.VAULT.idFromName(n),
      get: () => ({
        handle: () => {
          throw new Error(`storage exploded near ${CANARY_VALUE}`);
        },
      }),
    } as unknown as Env['VAULT'];
    const res = await fx.get(fx.owner, '/changes', { env: { VAULT: failing } });
    expect(res.status).toBe(500);
    expect(JSON.stringify(res.json)).not.toContain(CANARY_VALUE);
    expect(res.json.error.message).toBe('internal error');
    expect(logged()).not.toContain(CANARY_VALUE);
    expect((await fetchRaw('/healthz')).status).toBe(200);
  });
});

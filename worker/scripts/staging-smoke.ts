/**
 * End-to-end smoke test against a deployed STAGING Worker.
 *
 *   STAGING_ISSUER_PRIVATE_JWK_PATH=~/.ak-vault/staging-issuer-private-jwk.json \
 *     tsx scripts/staging-smoke.ts [https://vault-staging.agentkit.best] [proof-origin]
 *
 * `proof-origin` is only for a local `wrangler dev --env staging` run, where the
 * runtime rewrites request URLs to the route host with the local protocol; pass
 * http://vault-staging.agentkit.best so AKV-Proof binds the URL the Worker sees.
 *
 * Creates a throwaway vault with synthetic keys and data, then checks: healthz,
 * meta, genesis (with the owner wrap), enrolling a second device with its wrap
 * (checked against the signed digest),
 * a write, a CAS conflict that is preserved, and that a stale offline write
 * cannot resurrect a deleted item. Prints only step names and HTTP statuses —
 * never keys, tokens, proofs or response bodies. Exits non-zero on any failure.
 */
import { readFileSync } from 'node:fs';
import {
  b64encode,
  buildGenesisEvent,
  buildProof,
  createDeviceKeys,
  nextMembershipEvent,
  randomBytes,
  randomId,
  sealItem,
  signKeyPairFromSeed,
  signRecord,
  utf8Encode,
  verifyDeviceWraps,
  verifyMembershipChain,
  wrapToDevice,
  wrapsDigest,
  type DeviceKeys,
  type ItemPayload,
  type TombstonePayload,
  type JsonObject,
} from '@ak-vault/protocol';

const ISSUER = 'https://staging-test-issuer.ak-vault.invalid';
const AUDIENCE = 'https://vault-staging.agentkit.best';
const base = new URL(process.argv[2] ?? 'https://vault-staging.agentkit.best').origin;
const proofOrigin = new URL(process.argv[3] ?? base).origin;

function fail(message: string): never {
  process.stderr.write(`FAIL ${message}\n`);
  process.exit(1);
}

function loadIssuerKey(): Promise<{ key: CryptoKey; kid: string }> {
  const path = process.env['STAGING_ISSUER_PRIVATE_JWK_PATH'];
  if (!path) fail('STAGING_ISSUER_PRIVATE_JWK_PATH is not set');
  let jwk: JsonWebKey & { kid?: string };
  try {
    jwk = JSON.parse(readFileSync(path, 'utf8')) as JsonWebKey & { kid?: string };
  } catch {
    fail('cannot read the staging issuer key file');
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.kid?.startsWith('staging-test-')) fail('key file is not a staging test ES256 private JWK');
  const kid = jwk.kid;
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']).then((key) => ({ key, kid }));
}

const issuer = await loadIssuerKey();
const part = (v: unknown) => b64encode(utf8Encode(JSON.stringify(v)));

async function mintToken(account: string, device: DeviceKeys): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: account, did: device.record.device_id, sid: `smoke-${randomId()}`, jti: randomId(), scope: 'vault:read vault:write', iat: now, nbf: now, exp: now + 120 };
  const input = `${part({ alg: 'ES256', typ: 'JWT', kid: issuer.kid })}.${part(claims)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, issuer.key, new Uint8Array(utf8Encode(input))));
  return `${input}.${b64encode(sig)}`;
}

interface Result {
  status: number;
  json: Record<string, unknown> | null;
}

async function request(device: DeviceKeys | null, account: string, method: string, path: string, body?: unknown): Promise<Result> {
  const url = `${base}${path}`;
  const bytes = body === undefined ? new Uint8Array() : utf8Encode(JSON.stringify(body));
  const headers: Record<string, string> = {};
  if (device) {
    const token = await mintToken(account, device);
    headers['Authorization'] = `Bearer ${token}`;
    headers['AKV-Proof'] = buildProof({ htm: method, htu: `${proofOrigin}${path}`, ts: Date.now(), token, body: bytes, secretKey: device.signSecret });
  }
  if (method !== 'GET') headers['Idempotency-Key'] = randomId();
  if (bytes.length > 0) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(url, { method, headers, ...(method === 'GET' ? {} : { body: new Uint8Array(bytes) }), signal: AbortSignal.timeout(15_000) });
  } catch {
    fail(`${method} ${path.replace(/[A-Za-z0-9_-]{22}/g, ':id')} network error`);
  }
  const text = await res.text();
  let json: Record<string, unknown> | null = null;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

function expectStatus(step: string, res: Result, status: number, code?: string): void {
  const got = (res.json?.['error'] as { code?: string } | undefined)?.code;
  if (res.status !== status || (code && got !== code)) fail(`${step}: expected ${status}${code ? ` ${code}` : ''}, got ${res.status}${got ? ` ${got}` : ''}`);
  process.stdout.write(`ok   ${step} (${res.status}${code ? ` ${code}` : ''})\n`);
}

// Synthetic vault and devices.
const account = `smoke-${randomId()}`;
const owner = createDeviceKeys({ account, role: 'owner', kind: 'human' });
const laptop = createDeviceKeys({ account, role: 'owner', kind: 'human' });
const vaultId = randomId();
const vk = randomBytes(32);
const recovery = signKeyPairFromSeed(randomBytes(32));
const v = `/v1/vaults/${vaultId}`;

function record(device: DeviceKeys, itemId: string, base: number, value: string | null) {
  const tombstone = value === null;
  const payload: ItemPayload | TombstonePayload = tombstone ? { deleted: true } : { name: 'SMOKE_SYNTHETIC', value, meta: {}, sensitivity: 'normal' };
  const author = device.record.device_id;
  const env = sealItem({ vk, vault_id: vaultId, item_id: itemId, base_revision: base, key_epoch: 1, author, tombstone, payload });
  return signRecord({ vault_id: vaultId, item_id: itemId, base_revision: base, key_epoch: 1, tombstone, author, ts: Date.now(), resolves: [], env }, device.signSecret);
}

expectStatus('healthz', await request(null, account, 'GET', '/healthz'), 200);
const meta = await request(null, account, 'GET', '/v1/meta');
expectStatus('meta', meta, 200);
if (meta.json?.['sync_enabled'] !== true) fail('sync is disabled on the target');

// Wraps are made first: each device-adding event signs the digest of its wrap set.
const ownerWrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: owner.record });
const genesis = buildGenesisEvent(
  {
    vault_id: vaultId,
    ts: Date.now(),
    author: owner.record.device_id,
    body: { vault_kind: 'personal', owner_account: account, recovery_sign_pub: b64encode(recovery.publicKey), devices: [owner.record as unknown as JsonObject], wraps_digest: wrapsDigest([ownerWrap]) },
  },
  owner.signSecret,
);
expectStatus('genesis', await request(owner, account, 'PUT', v, { event: genesis, wraps: [ownerWrap] }), 201);

const state = verifyMembershipChain([genesis]);
const laptopWrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: laptop.record });
const add = nextMembershipEvent(
  state,
  { type: 'device_add', ts: Date.now(), author: owner.record.device_id, body: { device: laptop.record as unknown as JsonObject, sas: b64encode(randomBytes(32)), wraps_digest: wrapsDigest([laptopWrap]) } },
  owner.signSecret,
);
expectStatus('enroll device with wrap', await request(owner, account, 'POST', `${v}/membership`, { event: add, wraps: [laptopWrap] }), 201);
const wraps = await request(laptop, account, 'GET', `${v}/wraps?membership_seq=1`);
expectStatus('fetch signed wrap set', wraps, 200);
verifyDeviceWraps(add, (wraps.json?.['wraps'] ?? []) as unknown[]);

const itemId = randomId();
expectStatus('write', await request(owner, account, 'PUT', `${v}/items/${itemId}`, record(owner, itemId, 0, 'synthetic-1')), 200);
expectStatus('CAS advance', await request(laptop, account, 'PUT', `${v}/items/${itemId}`, record(laptop, itemId, 1, 'synthetic-2')), 200);
const stale = record(owner, itemId, 1, 'synthetic-stale');
expectStatus('CAS conflict preserved', await request(owner, account, 'PUT', `${v}/items/${itemId}`, stale), 409, 'conflict');
const offline = record(laptop, itemId, 2, 'synthetic-offline');
expectStatus('delete', await request(owner, account, 'PUT', `${v}/items/${itemId}`, record(owner, itemId, 2, null)), 200);
expectStatus('no resurrection', await request(laptop, account, 'PUT', `${v}/items/${itemId}`, offline), 409, 'tombstoned');
const changes = await request(laptop, account, 'GET', `${v}/changes`);
expectStatus('pull changes', changes, 200);
const kinds = (changes.json?.['changes'] as { kind: string }[] | undefined)?.map((c) => c.kind) ?? [];
if (!kinds.includes('conflict')) fail('pull did not return the preserved conflict branch');
process.stdout.write('smoke passed\n');

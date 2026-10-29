/**
 * End-to-end smoke test against a deployed STAGING Worker, with vault tokens
 * minted by ak-web staging exactly as a real client gets them.
 *
 *   AK_STAGING_SESSION_TOKEN_PATH=<file holding an ak staging CLI session token> \
 *     tsx scripts/staging-smoke.ts [https://vault-staging.agentkit.best] [proof-origin]
 *   AK_STAGING_SESSION_TOKEN_PATH=<file> tsx scripts/staging-smoke.ts --remote-access
 *
 * Optional: AK_STAGING_WEB_ORIGIN (ak-web origin that mints tokens, default
 * https://staging.agentkit.best) and AK_STAGING_SMOKE_STATE_PATH (device key state,
 * default ~/.ak-vault/staging-smoke-devices.json). The session must be an email
 * sign-in device session; ak CLI session tokens are short-lived, so refresh the
 * file right before a run.
 *
 * `--remote-access` adds the remote-access checks (staging-smoke-remote-access.ts):
 * healthz reports remote_access, the `/mcp` challenge and protected-resource metadata,
 * the authorization-server metadata (ak-web), and audience refusals. Without a session
 * file it runs only the public part. Optional AK_STAGING_MCP_TOKEN_PATH is a file holding
 * an MCP access token minted for `<audience>/mcp` by a consented client; with it the
 * smoke also refuses that token on the sync API and accepts it on `/mcp`. Steps that
 * need a human (connected-app revoke) or the e2e leak scan are printed as `pending`,
 * never as passed. Exit codes: 0 passed, 1 failed, 3 blocked by the target environment
 * (for example, remote access is not deployed or ak-web answers 503).
 *
 * `proof-origin` is only for a local `wrangler dev --env staging` run, where the
 * runtime rewrites request URLs to the route host with the local protocol; pass
 * http://vault-staging.agentkit.best so AKV-Proof binds the URL the Worker sees.
 *
 * The vault account is the token `sub`. The two smoke devices are reused across
 * runs (see staging-smoke-device-state.ts) because ak-web binds device keys per
 * account and caps them; each run creates a fresh vault, which the Worker does not
 * cap per account. Checks: healthz, meta (sync on, issuer matches ak-web's tokens),
 * genesis (with the owner wrap), enrolling a second device with its wrap (checked
 * against the signed digest), a write, a CAS conflict that is preserved, and that a
 * stale offline write cannot resurrect a deleted item. Prints only step names, HTTP
 * statuses and stable error codes: never keys, tokens, proofs or response bodies.
 * Exits non-zero on any failure.
 */
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
import { DEFAULT_AK_WEB_ORIGIN, fail, parseSecureOrigin, readCliSession, reportSmokeFailure, vaultTokenSource } from './staging-smoke-ak-web-token.js';
import { DEFAULT_STATE_PATH, loadDeviceSecrets, type DeviceSecrets } from './staging-smoke-device-state.js';
import {
  BlockedError,
  checkDiscoveryAndAudience,
  checkMcpTokenAudience,
  markPending,
  pendingCount,
  requireRemoteAccessFlag,
  REMOTE_AUDIENCE,
  runPublicRemoteAccessChecks,
} from './staging-smoke-remote-access.js';

/** A smoke device: its protocol keys plus the label and seed its tokens are minted with. */
interface SmokeDevice {
  label: string;
  keys: DeviceKeys;
  secrets: DeviceSecrets;
}

interface Result {
  status: number;
  json: Record<string, unknown> | null;
}

async function main(): Promise<void> {
  const AUDIENCE = REMOTE_AUDIENCE;
  const remoteAccess = process.argv.includes('--remote-access');
  const positional = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));
  const base = parseSecureOrigin(positional[0] ?? 'https://vault-staging.agentkit.best', 'the Worker URL');
  const proofOrigin = new URL(positional[1] ?? base).origin;
  const akWebOrigin = parseSecureOrigin(process.env['AK_STAGING_WEB_ORIGIN'] || DEFAULT_AK_WEB_ORIGIN, 'AK_STAGING_WEB_ORIGIN');

  // Without a signed-in session only the public remote-access checks can run.
  if (remoteAccess && !process.env['AK_STAGING_SESSION_TOKEN_PATH']) {
    await runPublicRemoteAccessChecks(base, akWebOrigin);
    return;
  }

  const session = readCliSession(process.env['AK_STAGING_SESSION_TOKEN_PATH']);
  const secrets = loadDeviceSecrets(process.env['AK_STAGING_SMOKE_STATE_PATH'] || DEFAULT_STATE_PATH, session.userId, ['owner', 'laptop']);
  const tokenFor = vaultTokenSource({ akWebOrigin, audience: AUDIENCE, session });

  async function request(device: SmokeDevice | null, method: string, path: string, body?: unknown): Promise<Result> {
    const url = `${base}${path}`;
    const bytes = body === undefined ? new Uint8Array() : utf8Encode(JSON.stringify(body));
    const headers: Record<string, string> = {};
    if (device) {
      const { token } = await tokenFor(device.label, device.secrets.signSeed);
      headers['Authorization'] = `Bearer ${token}`;
      headers['AKV-Proof'] = buildProof({ htm: method, htu: `${proofOrigin}${path}`, ts: Date.now(), token, body: bytes, secretKey: device.keys.signSecret });
    }
    if (method !== 'GET') headers['Idempotency-Key'] = randomId();
    if (bytes.length > 0) headers['Content-Type'] = 'application/json';
    let res: Response;
    try {
      res = await fetch(url, { method, headers, ...(method === 'GET' ? {} : { body: new Uint8Array(bytes) }), redirect: 'error', signal: AbortSignal.timeout(15_000) });
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

  const health = await request(null, 'GET', '/healthz');
  expectStatus('healthz', health, 200);
  if (remoteAccess) requireRemoteAccessFlag(health);
  const meta = await request(null, 'GET', '/v1/meta');
  expectStatus('meta', meta, 200);
  if (meta.json?.['sync_enabled'] !== true) fail('sync is disabled on the target');
  const auth = meta.json?.['auth'] as { issuer?: unknown; audience?: unknown } | undefined;
  if (auth?.audience !== AUDIENCE) fail('the target does not use the staging audience');

  // The vault account is whoever ak-web says the session belongs to: the token `sub`.
  const ownerToken = await tokenFor('owner', (secrets['owner'] as DeviceSecrets).signSeed);
  if (ownerToken.iss !== auth.issuer) fail('the target does not trust the issuer of ak-web tokens');
  if (ownerToken.sub !== session.userId) fail('ak-web minted a token for a different account than the session');
  const account = ownerToken.sub;
  if ((await tokenFor('laptop', (secrets['laptop'] as DeviceSecrets).signSeed)).sub !== account) fail('ak-web minted device tokens for different accounts');
  if (remoteAccess) await checkDiscoveryAndAudience(base, String(auth.issuer), akWebOrigin, ownerToken.token);

  function smokeDevice(label: string): SmokeDevice {
    const deviceSecrets = secrets[label] as DeviceSecrets;
    return { label, secrets: deviceSecrets, keys: createDeviceKeys({ account, role: 'owner', kind: 'human', signSeed: deviceSecrets.signSeed, kxSecret: deviceSecrets.kxSecret }) };
  }

  // Synthetic vault on the persistent smoke devices.
  const ownerDevice = smokeDevice('owner');
  const laptopDevice = smokeDevice('laptop');
  const owner = ownerDevice.keys;
  const laptop = laptopDevice.keys;
  const vaultId = randomId();
  const vk = randomBytes(32);
  const recovery = signKeyPairFromSeed(randomBytes(32));
  const v = `/v1/vaults/${vaultId}`;

  function record(device: DeviceKeys, itemId: string, revision: number, value: string | null) {
    const tombstone = value === null;
    const payload: ItemPayload | TombstonePayload = tombstone ? { deleted: true } : { name: 'SMOKE_SYNTHETIC', value, meta: {}, sensitivity: 'normal' };
    const author = device.record.device_id;
    const env = sealItem({ vk, vault_id: vaultId, item_id: itemId, base_revision: revision, key_epoch: 1, author, tombstone, payload });
    return signRecord({ vault_id: vaultId, item_id: itemId, base_revision: revision, key_epoch: 1, tombstone, author, ts: Date.now(), resolves: [], env }, device.signSecret);
  }

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
  expectStatus('genesis', await request(ownerDevice, 'PUT', v, { event: genesis, wraps: [ownerWrap] }), 201);

  const state = verifyMembershipChain([genesis]);
  const laptopWrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: laptop.record });
  const add = nextMembershipEvent(
    state,
    { type: 'device_add', ts: Date.now(), author: owner.record.device_id, body: { device: laptop.record as unknown as JsonObject, sas: b64encode(randomBytes(32)), wraps_digest: wrapsDigest([laptopWrap]) } },
    owner.signSecret,
  );
  expectStatus('enroll device with wrap', await request(ownerDevice, 'POST', `${v}/membership`, { event: add, wraps: [laptopWrap] }), 201);
  const wraps = await request(laptopDevice, 'GET', `${v}/wraps?membership_seq=1`);
  expectStatus('fetch signed wrap set', wraps, 200);
  verifyDeviceWraps(add, (wraps.json?.['wraps'] ?? []) as unknown[]);

  const itemId = randomId();
  expectStatus('write', await request(ownerDevice, 'PUT', `${v}/items/${itemId}`, record(owner, itemId, 0, 'synthetic-1')), 200);
  expectStatus('CAS advance', await request(laptopDevice, 'PUT', `${v}/items/${itemId}`, record(laptop, itemId, 1, 'synthetic-2')), 200);
  const stale = record(owner, itemId, 1, 'synthetic-stale');
  expectStatus('CAS conflict preserved', await request(ownerDevice, 'PUT', `${v}/items/${itemId}`, stale), 409, 'conflict');
  const offline = record(laptop, itemId, 2, 'synthetic-offline');
  expectStatus('delete', await request(ownerDevice, 'PUT', `${v}/items/${itemId}`, record(owner, itemId, 2, null)), 200);
  expectStatus('no resurrection', await request(laptopDevice, 'PUT', `${v}/items/${itemId}`, offline), 409, 'tombstoned');
  const changes = await request(laptopDevice, 'GET', `${v}/changes`);
  expectStatus('pull changes', changes, 200);
  const kinds = (changes.json?.['changes'] as { kind: string }[] | undefined)?.map((c) => c.kind) ?? [];
  if (!kinds.includes('conflict')) fail('pull did not return the preserved conflict branch');

  if (remoteAccess) {
    await checkMcpTokenAudience(base, v);
    markPending('step 9, revoked MCP client refused', 'needs a connected-apps revoke in ak-web between two runs (a human action)');
    markPending('step 11, live leak scan', 'the e2e suite runs the wrangler tail leak scan (e2e/remote-access/leak-scan.ts)');
  }
  process.stdout.write(pendingCount() > 0 ? `smoke checks passed; ${pendingCount()} step(s) pending and not checked\n` : 'smoke passed\n');
}

try {
  await main();
} catch (err) {
  if (err instanceof BlockedError) {
    process.stderr.write(`BLOCKED ${err.message}\n`);
    process.exitCode = err.exitCode;
  } else if (!reportSmokeFailure(err)) {
    throw err;
  }
}

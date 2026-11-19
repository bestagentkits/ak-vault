/**
 * Sandbox lease test helpers (spec §3.14, §9.6): a sandbox with in-memory lease and request
 * keys (never a vault device), and calls through the real Worker with the lease flag on.
 */
import { b64encode, deviceIdFromSignPub, generateLeaseKeys, sealLeaseRequest, signLeaseGrant, type LeaseDecision, type LeasePayload, type LeaseRequestWire } from '@ak-vault/protocol';
import { call, type CallOptions, type CallResult, type TestDevice } from './api-client.js';
import { publishSealKey } from './mcp-client.js';
import type { VaultFixture } from './vault-fixture.js';

export const LEASES_ON = { VAULT_LEASES_ENABLED: 'true' } as const;

export interface Sandbox {
  /** The request key presented as a device (token `did` = kid(request key), never enrolled). */
  device: TestDevice;
  leaseSecret: Uint8Array;
  leasePub: Uint8Array;
}

export function newSandbox(account: string): Sandbox {
  const keys = generateLeaseKeys();
  const signPub = b64encode(keys.requestPub);
  return {
    device: {
      keys: {
        record: { device_id: deviceIdFromSignPub(signPub), sign_pub: signPub, kx_pub: b64encode(keys.leasePub), account, role: 'editor', kind: 'human' },
        signSecret: keys.requestSeed,
        kxSecret: keys.leaseSecret,
      },
      account,
      sid: `sid-sandbox-${deviceIdFromSignPub(signPub)}`,
    },
    leaseSecret: keys.leaseSecret,
    leasePub: keys.leasePub,
  };
}

export const leasesPath = (fx: VaultFixture, rest = '') => `/v1/vaults/${fx.vaultId}/leases${rest}`;

/** A lease-identity call: `api_key_device` session, `AKV-Device-Key` = the request key, flag on. */
export function sandboxCall(sb: Sandbox, method: string, path: string, body?: unknown, opts: CallOptions = {}): Promise<CallResult> {
  return call(sb.device, method, path, body, {
    sessionKind: 'api_key_device',
    ...opts,
    headers: { 'AKV-Device-Key': sb.device.keys.record.sign_pub, ...opts.headers },
    env: { ...LEASES_ON, ...opts.env },
  });
}

/** A member-device call with the flag on. */
export function memberCall(device: TestDevice, method: string, path: string, body?: unknown, opts: CallOptions = {}): Promise<CallResult> {
  return call(device, method, path, body, { ...opts, env: { ...LEASES_ON, ...opts.env } });
}

export const SUBJECT = { secrets: [{ var: 'SENTINEL_LEASE_VAR', ref: 'SENTINEL_LEASE_REF_7c2a' }], purpose: 'SENTINEL_LEASE_PURPOSE' };
export const VALUE = 'sentinel-lease-value-91f3';

/** Publish the seal key and return its `seal_pub` as the sandbox reads it. */
export async function sealPubFor(fx: VaultFixture, sb: Sandbox): Promise<string> {
  await publishSealKey(fx);
  const res = await sandboxCall(sb, 'GET', leasesPath(fx, '/seal-key'));
  if (res.status !== 200) throw new Error(`seal-key read failed: ${res.status}`);
  return res.json.seal_key.seal_pub as string;
}

export interface RequestOpts {
  ts?: number;
  life?: number;
  ttlS?: number;
  epoch?: number;
  account?: string;
  vaultId?: string;
}

export function buildRequest(fx: VaultFixture, sb: Sandbox, sealPub: string, opts: RequestOpts = {}): LeaseRequestWire {
  const ts = opts.ts ?? Date.now();
  return sealLeaseRequest(sb.device.keys.signSecret, {
    vaultId: opts.vaultId ?? fx.vaultId,
    keyEpoch: opts.epoch ?? fx.keyEpoch,
    account: opts.account ?? sb.device.account,
    sealPub,
    leasePub: sb.leasePub,
    ttlS: opts.ttlS ?? 3600,
    ts,
    expiresAt: ts + (opts.life ?? 600_000),
    subject: SUBJECT,
  });
}

export function signGrant(approver: TestDevice, wire: LeaseRequestWire, decision: LeaseDecision, opts: { ts?: number; expiresAt?: number; payload?: LeasePayload } = {}) {
  return signLeaseGrant(approver.keys.signSecret, {
    request: wire,
    decision,
    approverKey: approver.keys.record.sign_pub,
    ts: opts.ts ?? Date.now(),
    requestedVars: SUBJECT.secrets.map((s) => s.var),
    ...(decision === 'allow' ? { payload: opts.payload ?? { secrets: [{ var: 'SENTINEL_LEASE_VAR', value: VALUE }] } } : {}),
    ...(opts.expiresAt === undefined ? {} : { expiresAt: opts.expiresAt }),
  });
}

/** A sandbox with the seal key read and one request posted. */
export async function postedLease(fx: VaultFixture, opts: RequestOpts & { sandbox?: Sandbox } = {}): Promise<{ sb: Sandbox; wire: LeaseRequestWire }> {
  const sb = opts.sandbox ?? newSandbox(fx.owner.account);
  const wire = buildRequest(fx, sb, await sealPubFor(fx, sb), opts);
  const res = await sandboxCall(sb, 'POST', leasesPath(fx), { request: wire });
  if (res.status !== 200) throw new Error(`lease post failed: ${res.status} ${JSON.stringify(res.json)}`);
  return { sb, wire };
}

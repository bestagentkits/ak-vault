/**
 * Calls the real Worker entry (and through it the real Durable Objects) with a
 * device-bound token and a signed AKV-Proof, the way a client would.
 */
import { env } from 'cloudflare:workers';
import { buildProof, createDeviceKeys, randomId, utf8Encode, type DeviceKeys, type DeviceKind, type Role } from '@ak-vault/protocol';
import worker from '../../src/index.js';
import type { Env } from '../../src/env.js';
import { mintToken } from './issuer.js';

export const BASE = 'https://vault.agentkit.best';

export interface TestDevice {
  keys: DeviceKeys;
  account: string;
  sid: string;
}

export function createDevice(account: string, role: Role = 'owner', kind: DeviceKind = 'human'): TestDevice {
  return { keys: createDeviceKeys({ account, role, kind }), account, sid: `sid-${randomId()}` };
}

export interface CallOptions {
  /** Explicit token; default mints one for the device. `null` sends none. */
  token?: string | null;
  scope?: string;
  /** Explicit proof header; `null` sends none. */
  proof?: string | null;
  /** Sign the proof with another key (stolen-token scenario). */
  proofSecret?: Uint8Array;
  /** Sign the proof for a different URL / body / method. */
  proofUrl?: string;
  proofBody?: Uint8Array;
  idempotencyKey?: string | null;
  env?: Partial<Env>;
  rawBody?: Uint8Array;
  headers?: Record<string, string>;
}

export interface CallResult {
  status: number;
  // Response JSON is untyped wire data; tests assert on its shape.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
  headers: Headers;
  token: string | null;
  proof: string | null;
}

export async function call(device: TestDevice | null, method: string, path: string, body?: unknown, opts: CallOptions = {}): Promise<CallResult> {
  const url = `${BASE}${path}`;
  const bytes = opts.rawBody ?? (body === undefined ? new Uint8Array() : utf8Encode(JSON.stringify(body)));
  const headers: Record<string, string> = { ...opts.headers };
  let token: string | null = null;
  if (opts.token !== undefined) token = opts.token;
  else if (device) token = await mintToken({ sub: device.account, did: device.keys.record.device_id, sid: device.sid, ...(opts.scope ? { scope: opts.scope } : {}) });
  if (token) headers['Authorization'] = `Bearer ${token}`;
  let proof: string | null = null;
  if (opts.proof !== undefined) proof = opts.proof;
  else if (device && token) {
    proof = buildProof({ htm: method, htu: opts.proofUrl ?? url, ts: Date.now(), token, body: opts.proofBody ?? bytes, secretKey: opts.proofSecret ?? device.keys.signSecret });
  }
  if (proof) headers['AKV-Proof'] = proof;
  const idem = opts.idempotencyKey === undefined ? (method === 'GET' ? null : randomId()) : opts.idempotencyKey;
  if (idem) headers['Idempotency-Key'] = idem;
  if (bytes.length > 0) headers['Content-Type'] = 'application/json';
  const init: RequestInit = { method, headers };
  if (method !== 'GET' && method !== 'HEAD') init.body = bytes;
  const response = await worker.fetch(new Request(url, init), { ...env, ...opts.env } as Env);
  const text = await response.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: response.status, json, headers: response.headers, token, proof };
}

/** Raw fetch through the Worker without auth (public routes, assets). */
export async function fetchRaw(path: string, init: RequestInit = {}, envOverride: Partial<Env> = {}): Promise<Response> {
  return worker.fetch(new Request(`${BASE}${path}`, init), { ...env, ...envOverride } as Env);
}

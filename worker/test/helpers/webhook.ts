/** Signs revocation webhook calls the way ak-web does (HMAC-SHA256 over `ts\n body`). */
import { env } from 'cloudflare:workers';
import { b64encode, concatBytes, randomId, utf8Encode } from '@ak-vault/protocol';
import type { Env } from '../../src/env.js';
import { fetchRaw } from './api-client.js';

export interface RevocationBody {
  v?: number;
  event_id?: string;
  revoke_sids?: string[];
  revoke_dids?: string[];
  min_iat?: { sub: string; iat: number }[];
}

export async function hmac(secret: string, ts: string, body: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', utf8Encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64encode(new Uint8Array(await crypto.subtle.sign('HMAC', key, concatBytes(utf8Encode(`${ts}\n`), body))));
}

export async function sendRevocation(
  body: RevocationBody,
  opts: { secret?: string; ts?: number; signature?: string; env?: Partial<Env>; raw?: Uint8Array } = {},
): Promise<Response> {
  const full = { v: 1, event_id: randomId(), revoke_sids: [], revoke_dids: [], min_iat: [], ...body };
  const bytes = opts.raw ?? utf8Encode(JSON.stringify(full));
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const signature = opts.signature ?? (await hmac(opts.secret ?? env.REVOCATION_WEBHOOK_SECRET!, ts, bytes));
  return fetchRaw(
    '/internal/v1/revocations',
    { method: 'POST', body: bytes, headers: { 'Content-Type': 'application/json', 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': signature } },
    opts.env ?? {},
  );
}

/** Request bodies are read with a streaming byte cap, so a chunked body without Content-Length cannot exceed the limit. */
import { env } from 'cloudflare:workers';
import { utf8Encode } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { readBodyCapped } from '../src/http/read-body-capped.js';
import { LIMITS } from '../src/limits.js';
import { fetchRaw } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { hmac } from './helpers/webhook.js';

/** A body stream of `total` bytes in 16 KiB chunks; reports how many bytes were pulled. */
function chunkedBody(total: number): { stream: ReadableStream<Uint8Array>; pulled: () => number } {
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= total) return controller.close();
      const n = Math.min(16 * 1024, total - sent);
      sent += n;
      controller.enqueue(new Uint8Array(n).fill(0x20));
    },
  });
  return { stream, pulled: () => sent };
}

async function expectQuota(promise: Promise<unknown>): Promise<void> {
  const err = await promise.then(
    () => null,
    (e: unknown) => e as { code?: string },
  );
  expect(err?.code).toBe('quota_exceeded');
}

describe('readBodyCapped', () => {
  it('reads a chunked body under the cap and stops early on one over it', async () => {
    const ok = chunkedBody(40_000);
    expect((await readBodyCapped(new Request('https://x.invalid/', { method: 'POST', body: ok.stream }), 64 * 1024)).length).toBe(40_000);

    const big = chunkedBody(10 * 1024 * 1024);
    const req = new Request('https://x.invalid/', { method: 'POST', body: big.stream });
    expect(req.headers.get('Content-Length')).toBeNull();
    await expectQuota(readBodyCapped(req, 64 * 1024));
    expect(big.pulled()).toBeLessThan(256 * 1024);
  });

  it('refuses a declared Content-Length over the cap without reading', async () => {
    const req = new Request('https://x.invalid/', { method: 'POST', body: 'x'.repeat(10), headers: { 'Content-Length': String(1 << 30) } });
    await expectQuota(readBodyCapped(req, 1024));
  });
});

describe('API and webhook routes', () => {
  it('a chunked API body over request_body_max_bytes is 413 quota_exceeded', async () => {
    const fx = await VaultFixture.create();
    const token = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id });
    const { stream } = chunkedBody(LIMITS.request_body_max_bytes + 1);
    const res = await fetchRaw(`/v1/vaults/${fx.vaultId}/audit`, { method: 'POST', body: stream, headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': 'k1' } });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('quota_exceeded');
  });

  it('a chunked revocation webhook body over 64 KiB is 413 quota_exceeded', async () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const { stream } = chunkedBody(64 * 1024 + 1);
    const signature = await hmac(env.REVOCATION_WEBHOOK_SECRET!, ts, utf8Encode(''));
    const res = await fetchRaw('/internal/v1/revocations', { method: 'POST', body: stream, headers: { 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': signature } });
    expect(res.status).toBe(413);
  });
});

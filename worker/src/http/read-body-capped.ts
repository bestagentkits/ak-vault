/**
 * Read a request body with a hard byte cap. A declared `Content-Length` over the
 * cap is refused before reading; otherwise the stream is consumed chunk by chunk
 * and abandoned as soon as the running total passes the cap, so a chunked body
 * without `Content-Length` never buffers more than `maxBytes` (+ one chunk).
 */
import { ApiError } from './errors.js';

export async function readBodyCapped(request: Request, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(request.headers.get('Content-Length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) throw new ApiError('quota_exceeded');
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ApiError('quota_exceeded');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

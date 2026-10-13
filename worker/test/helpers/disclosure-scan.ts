/**
 * Searches captured server-side text for a secret in every encoding a careless
 * code path might emit: UTF-8, hex, and base64/base64url at all three byte
 * alignments (so a canary embedded mid-buffer is still found).
 */
import { runInDurableObject } from 'cloudflare:test';
import { utf8Encode } from '@ak-vault/protocol';

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** All the forms in which `secret` could appear inside a larger text or encoded buffer. */
export function encodings(secret: string | Uint8Array): string[] {
  const bytes = typeof secret === 'string' ? utf8Encode(secret) : secret;
  const out = new Set<string>();
  if (typeof secret === 'string') out.add(secret);
  out.add([...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
  for (let k = 0; k < 3; k++) {
    const shifted = new Uint8Array(k + bytes.length);
    shifted.set(bytes, k);
    const b64 = toBase64(shifted);
    // Keep only the characters fully determined by the secret's bits.
    const core = b64.slice(Math.ceil((k * 8) / 6), Math.floor(((k + bytes.length) * 8) / 6));
    if (core.length >= 8) {
      out.add(core);
      out.add(core.replaceAll('+', '-').replaceAll('/', '_'));
    }
  }
  return [...out];
}

/** Return the first encoding of any secret found in `haystack`, or null. */
export function findLeak(haystack: string, secrets: readonly (string | Uint8Array)[]): string | null {
  for (const secret of secrets) for (const form of encodings(secret)) if (haystack.includes(form)) return form;
  return null;
}

function cellText(value: unknown): string {
  if (value instanceof ArrayBuffer) {
    const bytes = new Uint8Array(value);
    return `${new TextDecoder().decode(bytes)} ${toBase64(bytes)}`;
  }
  return String(value);
}

/** Every row of every application table in a SQLite-backed Durable Object, as text. */
export async function dumpDurableObject(stub: DurableObjectStub): Promise<{ tables: string[]; text: string }> {
  return runInDurableObject(stub, (_instance: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql;
    const tables = sql
      .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
      .toArray()
      .map((r) => r.name)
      .filter((n) => !n.startsWith('_cf_') && !n.startsWith('sqlite_'));
    const parts: string[] = [];
    for (const table of tables) {
      for (const row of sql.exec(`SELECT * FROM "${table}"`).toArray()) parts.push(Object.values(row).map(cellText).join(' '));
    }
    return { tables, text: parts.join('\n') };
  });
}

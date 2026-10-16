/**
 * Operator client for the Worker's point-in-time restore route
 * (`POST /internal/v1/operator`, see `src/routes/operator-restore.ts` and the
 * runbook "Durable Object backup and restore").
 *
 *   AKV_OPERATOR_SECRET_PATH=<0600 file outside the repo holding VAULT_OPERATOR_SECRET> \
 *     tsx scripts/operator-restore.ts <worker-origin> bookmark <vault_id> [<unix ms>]
 *     tsx scripts/operator-restore.ts <worker-origin> restore  <vault_id> <target-bookmark> <expected-current-bookmark>
 *
 * `bookmark` without a time returns the vault's current bookmark (exact); with a
 * time, the platform's approximate bookmark for it. `restore` needs the current
 * bookmark read just before (compare-and-swap) and prints the undo bookmark.
 * Prints the HTTP status and the response body, which holds only bookmarks or a
 * stable error code and fixed message; never the secret or the signature.
 */
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { b64encode, concatBytes, utf8Encode } from '@ak-vault/protocol';
import { assertOutsideRepo, assertPrivatePath, fail, parseSecureOrigin } from './staging-smoke-ak-web-token.js';

const SIGN_CONTEXT = 'akv1/operator-request';
const MIN_SECRET_LENGTH = 32;

export type OperatorAction =
  | { action: 'bookmark'; vault_id: string; at_ms: number | null }
  | { action: 'restore'; vault_id: string; bookmark: string; expected_current: string };

export function readOperatorSecret(path: string | undefined): string {
  if (!path) fail('AKV_OPERATOR_SECRET_PATH is not set');
  assertOutsideRepo(path, 'the operator secret file');
  let secret: string;
  try {
    assertPrivatePath(path, 'the operator secret file');
    secret = readFileSync(path, 'utf8').trim();
  } catch {
    return fail('cannot read the operator secret file');
  }
  if (secret.length < MIN_SECRET_LENGTH) fail('the operator secret is too short');
  return secret;
}

/** Signed request body: HMAC-SHA256 over the context line and the request JSON. */
export function signOperatorRequest(secret: string, origin: string, op: OperatorAction, nowMs = Date.now()): string {
  const request = JSON.stringify({ v: 1, origin, ts: Math.floor(nowMs / 1000), ...op });
  const mac = createHmac('sha256', secret).update(concatBytes(utf8Encode(`${SIGN_CONTEXT}\n`), utf8Encode(request))).digest();
  return JSON.stringify({ request, sig: b64encode(new Uint8Array(mac)) });
}

export async function sendOperatorRequest(secret: string, origin: string, op: OperatorAction): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${origin}/internal/v1/operator`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: signOperatorRequest(secret, origin, op),
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

function parseAction(args: string[]): OperatorAction {
  const [action, vaultId, a, b] = args;
  if (!vaultId) fail('usage: <origin> bookmark <vault_id> [<unix ms>] | <origin> restore <vault_id> <target> <expected-current>');
  if (action === 'bookmark') {
    if (a === undefined) return { action, vault_id: vaultId, at_ms: null };
    const at = Number(a);
    if (!Number.isSafeInteger(at)) fail('the time must be unix milliseconds');
    return { action, vault_id: vaultId, at_ms: at };
  }
  if (action === 'restore' && a && b) return { action, vault_id: vaultId, bookmark: a, expected_current: b };
  return fail('unknown action or missing arguments');
}

async function main(): Promise<void> {
  const [rawOrigin, ...rest] = process.argv.slice(2);
  const origin = parseSecureOrigin(rawOrigin ?? '', 'the Worker origin');
  const op = parseAction(rest);
  const secret = readOperatorSecret(process.env['AKV_OPERATOR_SECRET_PATH']);
  let result: { status: number; body: unknown };
  try {
    result = await sendOperatorRequest(secret, origin, op);
  } catch {
    return fail('the request did not complete');
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.status !== 200) process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main();

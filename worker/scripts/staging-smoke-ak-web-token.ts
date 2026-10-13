/**
 * Vault access tokens for the staging smoke, minted by ak-web
 * (`POST <ak-web origin>/api/agentkit/vault/token`) the way a real client gets them.
 *
 * Auth is an ak CLI session token (email OTP, carries a device-session `sessionId`)
 * as `Authorization: Bearer`. The body proves possession of the device's Ed25519 key:
 *
 *   {"sign_pub", "scope": [...], "ts": unix s, "sig"}
 *   sig = Ed25519 over utf8("akv1/vault-token-request") || 0x0A ||
 *         cjson({aud, scope (sorted), sid, sign_pub, ts})
 *
 * The signing input is built with the protocol library (`signDetached`); there is no
 * custom cryptography here. Every failure exits through `fail`, which prints a step
 * name, an HTTP status and at most ak-web's stable error code: never a token, key,
 * signature or response body.
 */
import { readFileSync, statSync } from 'node:fs';
import { b64decode, b64encode, deviceIdFromSignPub, signDetached, signKeyPairFromSeed, utf8Decode } from '@ak-vault/protocol';

export const VAULT_TOKEN_REQUEST_CONTEXT = 'akv1/vault-token-request';
export const DEFAULT_AK_WEB_ORIGIN = 'https://staging.agentkit.best';
const SCOPES = ['vault:read', 'vault:write'] as const;
const CLI_SESSION_PREFIX = 'ak_cli_';
/** ak-web's stable error codes are short snake_case words; anything else is not echoed. */
const ERROR_CODE = /^[a-z_]{1,64}$/;
/** Re-mint when a cached token has less than this left, so no request races its expiry. */
const REFRESH_MARGIN_SECONDS = 60;

export function fail(message: string): never {
  process.stderr.write(`FAIL ${message}\n`);
  process.exit(1);
}

/** Refuse a secret-bearing file that group or others can read (POSIX only). */
export function assertPrivateFile(path: string, what: string): void {
  if (process.platform === 'win32') return;
  if ((statSync(path).mode & 0o077) !== 0) fail(`${what} must not be readable by group or others (chmod 600)`);
}

/** HTTPS only; plain HTTP is allowed for a local ak-web on loopback. */
export function parseAkWebOrigin(raw: string | undefined): string {
  let url: URL;
  try {
    url = new URL(raw ?? DEFAULT_AK_WEB_ORIGIN);
  } catch {
    return fail('AK_STAGING_WEB_ORIGIN is not a URL');
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) fail('AK_STAGING_WEB_ORIGIN must be https (http only on loopback)');
  return url.origin;
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    const value: unknown = JSON.parse(utf8Decode(b64decode(parts[1] as string)));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export interface CliSession {
  token: string;
  /** Device-session ID the token request signature must bind (`sid`). */
  sessionId: string;
  userId: string;
}

/**
 * Read the ak CLI session token from `path`. Its claims are decoded, not verified:
 * ak-web verifies the token; the smoke only needs the `sessionId` it must sign and
 * an early, clear refusal for a token ak-web would reject anyway.
 */
export function readCliSession(path: string | undefined, nowSeconds = Math.floor(Date.now() / 1000)): CliSession {
  if (!path) fail('AK_STAGING_SESSION_TOKEN_PATH is not set');
  let token: string;
  try {
    assertPrivateFile(path, 'the session token file');
    token = readFileSync(path, 'utf8').trim();
  } catch {
    return fail('cannot read the session token file');
  }
  const claims = token.startsWith(CLI_SESSION_PREFIX) ? decodeJwtPayload(token.slice(CLI_SESSION_PREFIX.length)) : null;
  if (!claims) fail('the session token file does not hold an ak CLI session token');
  if (claims['authMethod'] !== 'email_otp' || typeof claims['sessionId'] !== 'string' || typeof claims['userId'] !== 'string') {
    fail('the session token is not an email sign-in device session (run `ak login` against staging)');
  }
  if (typeof claims['exp'] !== 'number' || claims['exp'] <= nowSeconds + REFRESH_MARGIN_SECONDS) fail('the session token has expired or is about to (sign in again)');
  return { token, sessionId: claims['sessionId'], userId: claims['userId'] };
}

/** The JSON body ak-web expects, signed by the device key it names. */
export function buildVaultTokenRequest(args: { audience: string; sessionId: string; signSeed: Uint8Array; ts: number }): Record<string, unknown> {
  const signPub = b64encode(signKeyPairFromSeed(args.signSeed).publicKey);
  const scope = [...SCOPES].sort();
  const sig = signDetached(VAULT_TOKEN_REQUEST_CONTEXT, { aud: args.audience, scope, sid: args.sessionId, sign_pub: signPub, ts: args.ts }, args.signSeed);
  return { sign_pub: signPub, scope, ts: args.ts, sig };
}

export interface VaultToken {
  token: string;
  /** Account the token is for; the smoke's vault account. */
  sub: string;
  iss: string;
  exp: number;
}

/** Mint one device token. `label` names the device in failure output only. */
export async function mintVaultToken(args: { akWebOrigin: string; audience: string; session: CliSession; signSeed: Uint8Array; label: string }): Promise<VaultToken> {
  const step = `mint ${args.label} token`;
  const body = buildVaultTokenRequest({ audience: args.audience, sessionId: args.session.sessionId, signSeed: args.signSeed, ts: Math.floor(Date.now() / 1000) });
  let res: Response;
  try {
    res = await fetch(`${args.akWebOrigin}/api/agentkit/vault/token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${args.session.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    return fail(`${step}: network error`);
  }
  let json: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = await res.json();
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) json = parsed as Record<string, unknown>;
  } catch {
    json = null;
  }
  if (res.status !== 200) {
    const code = json?.['errorCode'] ?? json?.['error'];
    const shown = typeof code === 'string' && ERROR_CODE.test(code) ? ` ${code}` : '';
    const hint = shown === ' device_revoked' || shown === ' device_conflict' ? ' (delete the smoke device state file to bind new device keys)' : '';
    return fail(`${step}: ak-web ${res.status}${shown}${hint}`);
  }
  const token = json?.['access_token'];
  const did = deviceIdFromSignPub(signKeyPairFromSeed(args.signSeed).publicKey);
  if (typeof token !== 'string' || json?.['did'] !== did) fail(`${step}: ak-web returned a malformed token response`);
  const claims: Record<string, unknown> = decodeJwtPayload(token) ?? {};
  const { sub, iss, exp, aud } = claims;
  if (typeof sub !== 'string' || sub.length === 0 || typeof iss !== 'string' || typeof exp !== 'number' || aud !== args.audience || claims['did'] !== did) {
    fail(`${step}: ak-web returned a token with unexpected claims`);
  }
  process.stdout.write(`ok   ${step} (${res.status})\n`);
  return { token, sub, iss, exp };
}

/** Per-device token cache that re-mints shortly before expiry. */
export function vaultTokenSource(args: { akWebOrigin: string; audience: string; session: CliSession }) {
  const cache = new Map<string, VaultToken>();
  return async (label: string, signSeed: Uint8Array): Promise<VaultToken> => {
    const cached = cache.get(label);
    if (cached && cached.exp - Math.floor(Date.now() / 1000) > REFRESH_MARGIN_SECONDS) return cached;
    const minted = await mintVaultToken({ ...args, signSeed, label });
    cache.set(label, minted);
    return minted;
  };
}

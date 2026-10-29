/** Test-only ES256 issuer: mints vault tokens with the per-run key from vitest.config.ts. */
import { env } from 'cloudflare:workers';
import { b64encode, randomId, utf8Encode } from '@ak-vault/protocol';

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_ISSUER_PRIVATE_JWK: string;
    }
  }
}

export const TEST_ISSUER = 'https://test-issuer.ak-vault.invalid';
export const TEST_AUDIENCE = 'https://vault.agentkit.best';

let signingKey: Promise<{ key: CryptoKey; kid: string }> | undefined;

function loadKey(): Promise<{ key: CryptoKey; kid: string }> {
  signingKey ??= (async () => {
    const jwk = JSON.parse(env.TEST_ISSUER_PRIVATE_JWK) as JsonWebKey & { kid: string };
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return { key, kid: jwk.kid };
  })();
  return signingKey;
}

const part = (value: unknown) => b64encode(utf8Encode(JSON.stringify(value)));

/** Sign arbitrary header/claims with the test key (ES256, raw r||s signature). */
export async function signJwt(header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const { key } = await loadKey();
  const input = `${part(header)}.${part(claims)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8Encode(input)));
  return `${input}.${b64encode(sig)}`;
}

export interface MintArgs {
  sub: string;
  did: string;
  sid?: string;
  scope?: string;
  /** Extra or replacement claims (undefined removes a claim). */
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
}

export async function mintToken(args: MintArgs): Promise<string> {
  const { kid } = await loadKey();
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    iss: TEST_ISSUER,
    aud: TEST_AUDIENCE,
    sub: args.sub,
    did: args.did,
    sid: args.sid ?? `sid-${randomId()}`,
    jti: randomId(),
    scope: args.scope ?? 'vault:read vault:write',
    iat: now,
    nbf: now,
    exp: now + 300,
    // ak-web sets the claim on every vault token; a test removes it with `session_kind: undefined`.
    session_kind: 'email_otp',
    ...args.claims,
  };
  for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
  return signJwt({ alg: 'ES256', typ: 'JWT', kid, ...args.header }, claims);
}

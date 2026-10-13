/**
 * Create a TEST-ONLY ES256 issuer key for the staging Worker.
 *
 *   tsx scripts/generate-staging-issuer-key.ts <private-jwk-output-path>
 *
 * Writes the private JWK (mode 0600) to the given path, which must be outside
 * this repository and must not exist yet, and prints ONLY the public JWKS JSON
 * to stdout for `env.staging.vars.VAULT_JWKS_JSON`. Never use this key in
 * production; production verifies tokens from ak-web's JWKS.
 */
import { createHash, webcrypto } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** RFC 7638 JWK thumbprint (base64url SHA-256 of the required members in order). */
function thumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash('sha256').update(canonical).digest('base64url');
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) fail('usage: generate-staging-issuer-key.ts <private-jwk-output-path>');
  const outPath = resolve(target);
  const rel = relative(REPO_ROOT, outPath);
  if (!rel.startsWith('..') && !rel.startsWith('/')) fail('refusing to write a private key inside the repository');
  if (existsSync(outPath)) fail('refusing to overwrite an existing file');

  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const priv = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
  const pub = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  if (!pub.x || !pub.y || !pub.crv || !pub.kty) fail('key export failed');
  const kid = `staging-test-${thumbprint({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }).slice(0, 16)}`;

  writeFileSync(outPath, `${JSON.stringify({ ...priv, kid, alg: 'ES256', use: 'sig' })}\n`, { mode: 0o600, flag: 'wx' });
  const jwks = { keys: [{ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, kid, alg: 'ES256', use: 'sig' }] };
  process.stdout.write(`${JSON.stringify(jwks)}\n`);
}

main().catch(() => fail('key generation failed'));

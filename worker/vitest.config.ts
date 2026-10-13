/**
 * Integration tests run inside workerd via @cloudflare/vitest-plugin with the
 * real Worker, real Durable Objects and real SQLite storage. A fresh TEST-ONLY
 * ES256 issuer key is generated per run: its public JWKS is bound as
 * VAULT_JWKS_JSON and its private JWK as TEST_ISSUER_PRIVATE_JWK so tests can
 * mint tokens. Nothing here is a real credential.
 */
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { unstable_readConfig } from 'wrangler';

const TEST_KID = 'test-issuer-key-1';
const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
const privateJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);

// Audiences as deployed, read from wrangler.jsonc so tests check the real configuration.
// `env: ''` selects the top level even when CLOUDFLARE_ENV is set in the shell.
const wranglerPath = fileURLToPath(new URL('./wrangler.jsonc', import.meta.url));
const deployedAudiences = Object.fromEntries(
  (['production', 'staging'] as const).map((name) => {
    const config = unstable_readConfig({ config: wranglerPath, env: name === 'production' ? '' : name }, {});
    return [name, config.vars['VAULT_AUDIENCE']];
  }),
);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          VAULT_SYNC_ENABLED: 'true',
          VAULT_ISSUER: 'https://test-issuer.ak-vault.invalid',
          VAULT_AUDIENCE: 'https://vault.agentkit.best',
          VAULT_JWKS_JSON: JSON.stringify({ keys: [{ ...publicJwk, kid: TEST_KID, alg: 'ES256', use: 'sig' }] }),
          TEST_ISSUER_PRIVATE_JWK: JSON.stringify({ ...privateJwk, kid: TEST_KID }),
          TEST_DEPLOYED_AUDIENCES: JSON.stringify(deployedAudiences),
          REVOCATION_WEBHOOK_SECRET: 'test-only-webhook-secret-0123456789abcdef',
        },
      },
    }),
  ],
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    // The workerd runner cannot read Vitest 5's on-disk transformed-module cache.
    fsModuleCache: false,
  },
});

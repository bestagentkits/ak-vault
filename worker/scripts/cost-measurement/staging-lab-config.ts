/**
 * Lab Worker config built from the STAGING environment of wrangler.jsonc: same
 * entry, compatibility date, observability, Durable Object classes and migrations.
 * Only the name (workers.dev, no route), the issuer (synthetic, inline JWKS) and
 * the secrets passed at deploy time differ. The file is written to the run's
 * private temporary directory, never to the repository.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { unstable_readConfig } from 'wrangler';
import { WORKER_DIR } from '../platform-log-scan/lab-worker-lifecycle.js';

export const STAGING_SCRIPT = 'ak-vault-staging';

export function writeStagingLabConfig(dir: string, name: string, vars: { issuer: string; audience: string; jwks: string }): string {
  const staging = unstable_readConfig({ config: join(WORKER_DIR, 'wrangler.jsonc'), env: 'staging' }, {});
  if (staging.name !== STAGING_SCRIPT) throw new Error('wrangler.jsonc staging environment not found');
  if (!staging.main || !staging.migrations?.length || !staging.durable_objects.bindings.length) throw new Error('staging config lacks its entry, migrations or Durable Object bindings');
  // The JWKS URL would be ignored next to the inline JWKS; leave it out so the lab trusts only the synthetic issuer.
  const { VAULT_JWKS_URL: _unused, ...stagingVars } = staging.vars as Record<string, unknown>;
  const config = {
    name,
    main: staging.main,
    compatibility_date: staging.compatibility_date,
    compatibility_flags: staging.compatibility_flags,
    workers_dev: true,
    preview_urls: false,
    observability: staging.observability,
    assets: { ...staging.assets, directory: join(WORKER_DIR, 'public') },
    durable_objects: { bindings: staging.durable_objects.bindings.map((b: { name: string; class_name: string }) => ({ name: b.name, class_name: b.class_name })) },
    migrations: staging.migrations,
    vars: { ...stagingVars, VAULT_ISSUER: vars.issuer, VAULT_AUDIENCE: vars.audience, VAULT_JWKS_JSON: vars.jwks },
  };
  const path = join(dir, 'wrangler.staging-lab.json');
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
  return path;
}

/**
 * Regenerate protocol/v1/vectors/*.json from fixed seeds. Usage: `pnpm vectors`.
 * `--check` verifies the committed files are up to date without writing.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildAllVectors } from './vectors/index.js';

export const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../../protocol/v1/vectors');

function main(): void {
  const check = process.argv.includes('--check');
  const files = buildAllVectors();
  let stale = 0;
  if (!check) mkdirSync(VECTORS_DIR, { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    const path = join(VECTORS_DIR, name);
    const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (current === text) continue;
    stale++;
    if (check) console.error(`stale: ${name}`);
    else writeFileSync(path, text);
  }
  console.log(check ? `${stale} stale vector file(s)` : `wrote ${stale} changed of ${Object.keys(files).length} vector files to ${VECTORS_DIR}`);
  if (check && stale > 0) process.exit(1);
}

main();

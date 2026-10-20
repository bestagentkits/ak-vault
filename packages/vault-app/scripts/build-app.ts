/**
 * Build the dashboard into `worker/public/app/`, which is committed: the deploy
 * step runs no bundler and no dev dependency, it only uploads these files. A
 * test (`test/build-staleness.test.ts`) rebuilds in memory and fails when the
 * committed output differs from the source.
 *
 * Output, all deterministic for a given source and esbuild version:
 *   index.html                  no inline script or style; every asset carries
 *                               sha384 Subresource Integrity and crossorigin
 *   assets/app.<sha256:8>.js    one minified ES module
 *   assets/app.<sha256:8>.css
 *
 * Usage: `pnpm --filter @ak-vault/vault-app build` (writes the files) or
 * `tsx scripts/build-app.ts --check` (exit 1 when the committed files are stale).
 */
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const PACKAGE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_OUT_DIR = resolve(PACKAGE_DIR, '../../worker/public/app');

function sha256Hex8(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex').slice(0, 8);
}

function sri(data: Uint8Array): string {
  return `sha384-${createHash('sha384').update(data).digest('base64')}`;
}

async function bundle(entry: string, loader: 'ts' | 'css'): Promise<Uint8Array> {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    write: false,
    minify: true,
    ...(loader === 'ts' ? { format: 'esm' as const } : {}),
    platform: 'browser',
    target: ['es2022', 'chrome120', 'firefox130', 'safari17'],
    legalComments: 'none',
    sourcemap: false,
    charset: 'utf8',
    logLevel: 'silent',
    absWorkingDir: PACKAGE_DIR,
  });
  const files = result.outputFiles ?? [];
  if (result.errors.length > 0 || files.length !== 1) throw new Error('esbuild failed');
  return files[0]!.contents;
}

function indexHtml(jsPath: string, jsSri: string, cssPath: string, cssSri: string): string {
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    '<meta name="robots" content="noindex, nofollow">',
    '<title>AgentKit Vault</title>',
    `<link rel="stylesheet" href="${cssPath}" integrity="${cssSri}" crossorigin="anonymous">`,
    `<script type="module" src="${jsPath}" integrity="${jsSri}" crossorigin="anonymous"></script>`,
    '</head>',
    '<body>',
    '<div id="app"><main><p>Loading…</p><noscript>The vault dashboard needs JavaScript.</noscript></main></div>',
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

/** Build every output file in memory, keyed by its path relative to the output directory. */
export async function buildApp(): Promise<Map<string, Uint8Array>> {
  const js = await bundle(join(PACKAGE_DIR, 'src/main.ts'), 'ts');
  const css = await bundle(join(PACKAGE_DIR, 'src/app.css'), 'css');
  const jsName = `assets/app.${sha256Hex8(js)}.js`;
  const cssName = `assets/app.${sha256Hex8(css)}.css`;
  const html = new TextEncoder().encode(indexHtml(`/app/${jsName}`, sri(js), `/app/${cssName}`, sri(css)));
  return new Map([
    ['index.html', html],
    [jsName, js],
    [cssName, css],
  ]);
}

/** Every file under `dir`, relative paths with "/" separators. */
export async function listFiles(dir: string, prefix = ''): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const e of entries) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await listFiles(join(dir, e.name), rel)));
    else out.push(rel);
  }
  return out.sort();
}

/** Paths that differ between a fresh build and `outDir` (missing, extra or changed). */
export async function staleFiles(outDir = DEFAULT_OUT_DIR): Promise<string[]> {
  const built = await buildApp();
  const onDisk = await listFiles(outDir);
  const stale = new Set<string>();
  for (const rel of onDisk) if (!built.has(rel)) stale.add(rel);
  for (const [rel, data] of built) {
    const existing = await readFile(join(outDir, rel)).catch(() => null);
    if (!existing || Buffer.compare(existing, Buffer.from(data)) !== 0) stale.add(rel);
  }
  return [...stale].sort();
}

export async function writeApp(outDir = DEFAULT_OUT_DIR): Promise<string[]> {
  const built = await buildApp();
  // The output directory belongs to this build alone: replace it whole.
  await rm(outDir, { recursive: true, force: true });
  for (const [rel, data] of built) {
    const path = join(outDir, rel);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, data);
  }
  return [...built.keys()].sort();
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const check = process.argv.includes('--check');
  const run = check ? staleFiles() : writeApp();
  run.then(
    (files) => {
      if (check && files.length > 0) {
        process.stderr.write(`dashboard build is stale: ${files.join(', ')}\nrun: pnpm --filter @ak-vault/vault-app build\n`);
        process.exit(1);
      }
      process.stdout.write(`${check ? 'up to date' : 'wrote'}: ${files.length === 0 ? 'no changes' : files.join(', ')}\n`);
    },
    (err: unknown) => {
      process.stderr.write(`dashboard build failed: ${err instanceof Error ? err.message : 'unknown error'}\n`);
      process.exit(1);
    },
  );
}

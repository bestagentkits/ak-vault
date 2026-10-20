/**
 * The committed bundle in worker/public/app is what deploys (the deploy step
 * runs no bundler). It must equal a fresh, deterministic build of this source.
 * Fix a failure with `pnpm --filter @ak-vault/vault-app build` and commit.
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_OUT_DIR, buildApp, staleFiles } from '../scripts/build-app.js';

describe('dashboard build', () => {
  it('committed output is up to date', async () => {
    expect(await staleFiles()).toEqual([]);
  });

  it('is deterministic', async () => {
    const a = await buildApp();
    const b = await buildApp();
    expect([...a.keys()]).toEqual([...b.keys()]);
    for (const [k, v] of a) expect(Buffer.compare(Buffer.from(v), Buffer.from(b.get(k)!)), k).toBe(0);
  });

  it('index.html loads only hashed same-origin assets with matching integrity and no inline code', async () => {
    const html = await readFile(join(DEFAULT_OUT_DIR, 'index.html'), 'utf8');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
    expect(html).not.toMatch(/<style\b|\sstyle=|\son[a-z]+=/i);
    const refs = [...html.matchAll(/(?:src|href)="([^"]+)" integrity="([^"]+)" crossorigin="anonymous"/g)];
    expect(refs.length).toBe(2);
    for (const [, path, integrity] of refs) {
      expect(path).toMatch(/^\/app\/assets\/app\.[0-9a-f]{8}\.(js|css)$/);
      const data = await readFile(join(DEFAULT_OUT_DIR, path!.slice('/app/'.length)));
      expect(`sha384-${createHash('sha384').update(data).digest('base64')}`).toBe(integrity);
    }
  });

  it('the bundle has no HTML sink, eval, console or third-party URL', async () => {
    const built = await buildApp();
    const js = new TextDecoder().decode([...built.entries()].find(([k]) => k.endsWith('.js'))![1]);
    for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'console.', 'localStorage']) {
      expect(js.includes(banned), banned).toBe(false);
    }
    expect(js).not.toMatch(/https?:\/\/[a-z0-9]/i);
  });
});

/**
 * Dashboard end-to-end flow against staging with a signed-in account and the phase-10
 * `ak` binary: sign in, enroll this browser by SAS, write-only set with the value-leak
 * round trip, an inert secret name, search by name and by provider metadata, delete, a
 * concurrent edit that must surface as a conflict, and removal of the browser device.
 * One shared browser context carries the device state through the serial steps: the
 * device keys are non-extractable, so every enrolled check lives here.
 *
 * The `ak` argument shapes below match `ak secrets --help` of the relay-capable build.
 * Device approval and removal stay with the operator: `ak` refuses an agent there, and
 * the suite never answers either prompt. Run it headed from your own terminal.
 */
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { AK_BIN, AK_OWNER_HOME, BASE_URL, STORAGE_STATE, gate, runNameSentinel, runSentinel } from './support/env.js';
import { setSecret, signIn } from './support/dashboard.js';
import { akHomeFromEnv, runAk } from './support/ak-cli.js';
import { capture, dumpPageState, type Capture } from './support/page-capture.js';

const g = await gate();
const reason = [g.remote, g.oauth, g.account, g.ak].find((r) => r !== null) ?? '';

test.describe.configure({ mode: 'serial' });

test.describe('dashboard flow (signed-in account, phase-10 ak)', () => {
  test.skip(reason !== '', reason);
  test.use({ storageState: STORAGE_STATE || undefined });

  let context: BrowserContext;
  let page: Page;
  let seen: Capture;
  let joinCode = '';

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ storageState: STORAGE_STATE || undefined });
    page = await context.newPage();
    seen = capture(page);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test('signs in and shows a join code for this new browser', async () => {
    await signIn(page);
    joinCode = ((await page.getByTestId('join-code').textContent()) ?? '').trim();
    expect(joinCode).toMatch(/^akj1-/);
  });

  test('enrolls the browser by SAS: the operator approves on the owner device by hand', async () => {
    // `ak secrets devices approve` must be answered by a person who compared both codes, so the
    // suite never answers it. Run headed: the operator pastes the offer and approves in a terminal.
    test.setTimeout(15 * 60_000);
    console.log(
      `[enroll] In your own terminal, with the owner HOME: ak secrets devices approve ${joinCode}\n` +
        '[enroll] Paste the printed offer code into this browser, continue, and answer y only if both codes match.\n' +
        '[enroll] The suite then presses "I approved it, continue" until the approval arrives.',
    );
    // Only the joining side is automated: the approval itself is the operator's answer in `ak`.
    const deadline = Date.now() + 14 * 60_000;
    while (!(await page.getByTestId('filter').isVisible())) {
      expect(Date.now(), 'the owner device did not approve this browser in time').toBeLessThan(deadline);
      const check = page.getByTestId('check-approval');
      if (await check.isVisible()) await check.click();
      await page.waitForTimeout(10_000);
    }
  });

  test('sets a value write-only and finds the item by name', async () => {
    const name = runNameSentinel();
    await setSecret(page, name, runSentinel());
    await expect(page.getByTestId('item-name').filter({ hasText: name })).toBeVisible({ timeout: 60_000 });
    await page.getByTestId('filter').fill(name);
    await expect(page.getByTestId('item')).toHaveCount(1);
    // No control shows, copies or reveals a value: the dashboard is write-only.
    await expect(page.getByRole('button', { name: /show|copy|reveal/i })).toHaveCount(0);
    // The dashboard shows names by design; the value must stay hidden everywhere, the name off the wire.
    await page.waitForLoadState('networkidle');
    expect(await dumpPageState(page)).not.toContain(runSentinel());
    expect(seen.bodies.some((b) => b.includes(runSentinel()) || b.includes(name))).toBe(false);
    expect(seen.console.some((c) => c.includes(runSentinel()) || c.includes(name))).toBe(false);
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });

  test('an injected image handler in a secret name does not execute and is shown as text', async () => {
    const name = `SMOKE_XSS_<img src=x onerror="window.__xssName=1">`;
    await page.getByTestId('filter').fill('');
    await setSecret(page, name, runSentinel());
    const item = page.getByTestId('item').filter({ hasText: 'SMOKE_XSS_' });
    await expect(item.getByTestId('item-name')).toHaveText(name, { timeout: 30_000 });
    expect(await page.evaluate(() => (window as unknown as { __xssName?: number }).__xssName)).toBeUndefined();
    expect(await page.locator('img[onerror]').count()).toBe(0);
    await item.getByTestId('delete').click();
    await item.getByTestId('confirm-delete').click();
    await expect(page.getByTestId('item').filter({ hasText: 'SMOKE_XSS_' })).toHaveCount(0, { timeout: 60_000 });
  });

  test('the value set in the browser reaches the owner device after one sync cycle', async () => {
    expect(await syncNow()).toBe(0);
    // Compared, never revealed: compare prints only match or differs.
    const compare = runAk(AK_BIN, ['secrets', 'compare', runNameSentinel(), '--value=-', '--json'], akHomeFromEnv(AK_OWNER_HOME));
    compare.end(runSentinel());
    await compare.waitFor(/"match"\s*:\s*true|"result"\s*:\s*"match"/, 60_000);
    expect(await compare.exit()).toBe(0);
  });

  test('finds the item by provider metadata set with ak annotate', async () => {
    const owner = runAk(AK_BIN, ['secrets', 'annotate', runNameSentinel(), '--provider', 'smoke-provider'], akHomeFromEnv(AK_OWNER_HOME));
    expect(await owner.exit()).toBe(0);
    expect(await syncNow()).toBe(0);
    await page.getByRole('button', { name: 'Refresh' }).click();
    await page.getByTestId('filter').fill('smoke-provider');
    await expect(page.getByTestId('item-name').filter({ hasText: runNameSentinel() })).toBeVisible({ timeout: 60_000 });
  });

  test('a concurrent edit from ak surfaces as a conflict on the next browser save', async () => {
    const name = runNameSentinel();
    await page.getByTestId('filter').fill('');
    await page.getByRole('button', { name: 'Refresh' }).click();
    const owner = runAk(AK_BIN, ['secrets', 'set', name, '--value=-', '--force'], akHomeFromEnv(AK_OWNER_HOME));
    owner.end(`${runSentinel()}-ak`);
    expect(await owner.exit()).toBe(0);
    expect(await syncNow()).toBe(0);
    await page.getByTestId('set-name').fill(name);
    await page.getByTestId('set-value').fill(`${runSentinel()}-browser`);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByTestId('notice')).toContainText('Another device changed this item', { timeout: 60_000 });
  });

  test('deletes an item for every device', async () => {
    await page.getByRole('button', { name: 'Refresh' }).click();
    await page.getByTestId('filter').fill(runNameSentinel());
    const item = page.getByTestId('item').filter({ hasText: runNameSentinel() });
    await item.getByTestId('delete').click();
    await item.getByTestId('confirm-delete').click();
    await expect(page.getByTestId('item').filter({ hasText: runNameSentinel() })).toHaveCount(0, { timeout: 60_000 });
  });

  test('the browser delete is gone from the owner device after one sync cycle', async () => {
    expect(await syncNow()).toBe(0);
    const get = runAk(AK_BIN, ['secrets', 'get', runNameSentinel(), '--json'], akHomeFromEnv(AK_OWNER_HOME));
    expect(await get.exit()).not.toBe(0);
  });

  test('removing this browser device closes the dashboard', async () => {
    // Removal rotates the vault key and needs the vault password and recovery key, so the
    // operator runs it by hand, as with approval.
    test.setTimeout(15 * 60_000);
    // A reload signs the dashboard out (tokens live in memory only); sign in again on the enrolled device.
    await signIn(page);
    await expect(page.getByTestId('filter')).toBeVisible({ timeout: 60_000 });
    // The header shows only a short device id; `ak` matches it against its own device list.
    const shortId = ((await page.locator('.device').textContent()) ?? '').replace(/^Device\s+/, '').trim();
    expect(shortId.length).toBeGreaterThan(0);
    console.log(`[remove] In your own terminal, with the owner HOME: ak secrets devices remove ${shortId} --reason retired`);
    // The browser learns of its removal on its next pull, so refresh until it does.
    const removed = page.getByText('This browser was removed from the vault.');
    const deadline = Date.now() + 14 * 60_000;
    while (!(await removed.isVisible())) {
      expect(Date.now(), 'the owner device did not remove this browser in time').toBeLessThan(deadline);
      const refresh = page.getByTestId('refresh');
      if (await refresh.isVisible()) await refresh.click();
      await page.waitForTimeout(10_000);
    }
  });
});

/** One `ak secrets sync now` cycle in the owner HOME; resolves with its exit code. */
async function syncNow(): Promise<number | null> {
  return runAk(AK_BIN, ['secrets', 'sync', 'now'], akHomeFromEnv(AK_OWNER_HOME)).exit(120_000);
}

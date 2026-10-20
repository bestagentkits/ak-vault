/**
 * Dashboard end-to-end flow against staging with a signed-in account and the phase-10
 * `ak` binary: sign in, enroll this browser by SAS, write-only set, search by name and
 * by provider metadata, delete, a concurrent edit that must surface as a conflict, and
 * removal of the browser device. One shared browser context carries the device state
 * through the serial steps.
 *
 * The `ak` argument shapes below follow the phase-10 relay client contract. They were
 * not exercised here because no phase-10 binary exists yet; verify them against
 * `ak secrets --help` on the first live run (see e2e/remote-access/README.md).
 */
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { AK_BIN, AK_OWNER_HOME, STORAGE_STATE, gate, runNameSentinel, runSentinel } from './support/env.js';
import { openDashboard, setSecret, signIn } from './support/dashboard.js';
import { akHomeFromEnv, runAk } from './support/ak-cli.js';

const g = await gate();
const reason = [g.remote, g.oauth, g.account, g.ak].find((r) => r !== null) ?? '';

test.describe.configure({ mode: 'serial' });

test.describe('dashboard flow (signed-in account, phase-10 ak)', () => {
  test.skip(reason !== '', reason);
  test.use({ storageState: STORAGE_STATE || undefined });

  let context: BrowserContext;
  let page: Page;
  let joinCode = '';

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ storageState: STORAGE_STATE || undefined });
    page = await context.newPage();
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test('signs in and shows a join code for this new browser', async () => {
    await signIn(page);
    joinCode = ((await page.getByTestId('join-code').textContent()) ?? '').trim();
    expect(joinCode).toMatch(/^akj1-/);
  });

  test('enrolls the browser by SAS: offer pasted, codes compared, approval confirmed on the owner device', async () => {
    const owner = runAk(AK_BIN, ['secrets', 'devices', 'approve', joinCode], akHomeFromEnv(AK_OWNER_HOME));
    try {
      const offer = await owner.waitFor(/\bako1-[A-Za-z0-9_-]+/, 120_000);
      await page.getByTestId('offer-input').fill(offer[0]);
      await page.getByRole('button', { name: 'Continue' }).click();
      const browserSas = ((await page.getByTestId('sas').textContent()) ?? '').replace(/\D/g, '');
      expect(browserSas).toHaveLength(6);
      const ownerSas = await owner.waitFor(/verification code:?\s*(\d{3})\s*(\d{3})/i, 60_000);
      // The owner approves only if both devices show the same code; a mismatch is an attack signal, so stop.
      if (`${ownerSas[1]}${ownerSas[2]}` !== browserSas) {
        owner.kill();
        throw new Error('SAS mismatch between the owner device and this browser: approval withheld');
      }
      owner.write('yes');
      expect(await owner.exit()).toBe(0);
    } finally {
      owner.kill();
    }
    await page.getByTestId('check-approval').click();
    await expect(page.getByTestId('filter')).toBeVisible({ timeout: 60_000 });
  });

  test('sets a value write-only and finds the item by name', async () => {
    const name = runNameSentinel();
    await setSecret(page, name, runSentinel());
    await expect(page.getByTestId('item-name').filter({ hasText: name })).toBeVisible({ timeout: 60_000 });
    await page.getByTestId('filter').fill(name);
    await expect(page.getByTestId('item')).toHaveCount(1);
    // No control shows, copies or reveals a value: the dashboard is write-only.
    await expect(page.getByRole('button', { name: /show|copy|reveal/i })).toHaveCount(0);
  });

  test('finds the item by provider metadata set with ak annotate', async () => {
    const owner = runAk(AK_BIN, ['secrets', 'annotate', runNameSentinel(), '--provider', 'smoke-provider'], akHomeFromEnv(AK_OWNER_HOME));
    expect(await owner.exit()).toBe(0);
    await page.getByRole('button', { name: 'Refresh' }).click();
    await page.getByTestId('filter').fill('smoke-provider');
    await expect(page.getByTestId('item-name').filter({ hasText: runNameSentinel() })).toBeVisible({ timeout: 60_000 });
  });

  test('a concurrent edit from ak surfaces as a conflict on the next browser save', async () => {
    const name = runNameSentinel();
    await page.getByTestId('filter').fill('');
    await page.getByRole('button', { name: 'Refresh' }).click();
    const owner = runAk(AK_BIN, ['secrets', 'set', name], akHomeFromEnv(AK_OWNER_HOME));
    owner.write(`${runSentinel()}-ak`);
    expect(await owner.exit()).toBe(0);
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

  test('removing this browser device closes the dashboard', async () => {
    await openDashboard(page);
    // The header shows only a short device id; `ak` matches it against its own device list.
    const shortId = ((await page.locator('.device').textContent()) ?? '').replace(/^Device\s+/, '').trim();
    expect(shortId.length).toBeGreaterThan(0);
    const owner = runAk(AK_BIN, ['secrets', 'devices', 'remove', shortId], akHomeFromEnv(AK_OWNER_HOME));
    expect(await owner.exit()).toBe(0);
    await expect(page.getByText('This browser was removed from the vault.')).toBeVisible({ timeout: 60_000 });
  });
});

/**
 * Page helpers for the `/app` dashboard. Selectors are the dashboard's own
 * `data-testid` hooks (packages/vault-app/src/ui/views.ts); no text scraping of
 * values. The helpers never log field contents.
 */
import { expect, type Page } from '@playwright/test';
import { BASE_URL } from './env.js';

export const APP_URL = `${BASE_URL}/app/`;

export async function openDashboard(page: Page): Promise<void> {
  await page.goto(APP_URL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByTestId('signin').or(page.getByTestId('lock')).or(page.getByTestId('offer-input')).or(page.getByTestId('sas')).or(page.getByTestId('filter'))).toBeVisible({ timeout: 30_000 });
}

/**
 * Signs in through ak-web (PKCE, `resource` bound to `/app`). The storage state supplies
 * the account's ak-web session; the consent step is the only other screen this drives.
 */
export async function signIn(page: Page): Promise<void> {
  await openDashboard(page);
  if (await page.getByTestId('signin').isVisible()) {
    await page.getByTestId('signin').click();
    const origin = new URL(BASE_URL).origin;
    // ak-web asks for consent until this account has granted the dashboard client.
    const allow = page.getByRole('button', { name: 'Allow access' });
    await expect(allow.or(page.locator('[data-testid]').first())).toBeVisible({ timeout: 90_000 });
    if (new URL(page.url()).origin !== origin && (await allow.isVisible())) await allow.click();
    await page.waitForURL((url) => url.origin === origin, { timeout: 90_000 });
    // The callback screen: the join code, the SAS check or the vault, never the loading screen.
    await expect(page.getByTestId('join-code').or(page.getByTestId('offer-input')).or(page.getByTestId('sas')).or(page.getByTestId('filter')).first()).toBeVisible({ timeout: 60_000 });
  }
}

/** Writes a secret through the dashboard form; the value is typed, never echoed by the helper. */
export async function setSecret(page: Page, name: string, value: string): Promise<void> {
  await page.getByTestId('set-name').fill(name);
  await page.getByTestId('set-value').fill(value);
  await page.getByRole('button', { name: 'Save' }).click();
}

/** Visible item names, as rendered. Used to assert presence without reading values. */
export async function listedNames(page: Page): Promise<string[]> {
  return page.getByTestId('item-name').allTextContents();
}

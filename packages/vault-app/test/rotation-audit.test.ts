// @vitest-environment happy-dom
/**
 * Rotation state changes append entries to the encrypted audit stream (spec §7).
 * Runs the real controller and protocol library against the in-memory world and
 * decrypts the stored stream as a vault member would.
 */
import { describe, expect, it } from 'vitest';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, byTestId, type Page } from './helpers/dashboard-page.js';

const SENTINEL = 'audit-sentinel-71be2c09';
const NEW_SENTINEL = 'audit-sentinel-new-4d08a1e3';
const NAME = 'audit-stripe-key';
const DAY_MS = 86_400_000;

async function open(world: FakeWorld): Promise<{ page: Page; itemId: string }> {
  const itemId = world.ownerSet(NAME, SENTINEL, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 100 * DAY_MS, rotate_ttl_days: 30 });
  const { page } = await new Browser(world).enroll();
  return { page, itemId };
}

describe('rotation audit entries', () => {
  it('appends one entry per state change, with no name, value or provider detail', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world);
    byTestId(page.root, 'rotate').click();

    await page.controller.startRotation(itemId);
    await page.controller.setRotationState(itemId, 'paused');
    await page.controller.setRotationState(itemId, 'active');
    await page.controller.setRotationState(itemId, 'failed');
    await page.controller.startRotation(itemId);
    await page.controller.rotate(itemId, NEW_SENTINEL);
    await page.controller.confirmRevoked(itemId);
    await page.controller.setRotationState(itemId, 'cancelled');
    await page.controller.setRotationState(itemId, null);

    const events = world.auditEvents();
    expect(events.map((e) => e['action'])).toEqual([
      'rotation_started', 'rotation_paused', 'rotation_resumed', 'rotation_failed', 'rotation_started',
      'rotation_vault_written', 'rotation_revoked', 'rotation_cancelled', 'rotation_cleared',
    ]);
    for (const e of events) {
      expect(Object.keys(e).sort()).toEqual(['action', 'device', 'item_id', 'ts', 'v']);
      expect(e).toMatchObject({ v: 1, item_id: itemId, device: expect.any(String) as unknown });
    }
    const wire = JSON.stringify(world.audit.map((a) => a.entry)) + world.exchanges.map((x) => x.requestBody).join('');
    const plain = JSON.stringify(events);
    for (const text of [plain, wire]) {
      expect(text).not.toContain(NAME);
      expect(text).not.toContain('audit-sentinel');
    }
    expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_updated' } });
  });

  it('writes nothing for a refused or failed rotation step, or for an interval edit', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world);
    await page.controller.startRotation(itemId);
    const before = world.audit.length;
    expect(await page.controller.confirmRevoked(itemId)).toBe(false); // vault value not written yet
    expect(await page.controller.rotate(itemId, SENTINEL)).toBe(false); // same value
    expect(await page.controller.setRotateTtl(itemId, 90)).toBe(true);
    expect(world.audit.length).toBe(before);
  });

  it('chains to the stored head and retries once when another device appended first', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world);
    world.appendAuditEntryAsOther();
    world.hostile.auditRaceOnce = true;
    await page.controller.startRotation(itemId);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_started' } });
    const events = world.auditEvents();
    expect(events.map((e) => e['action'])).toEqual(['other_device', 'other_device', 'rotation_started']);
    expect(world.auditPosts).toBe(2);
  });

  it('keeps the signed revision and says so when the audit stream is unavailable', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world);
    world.hostile.auditStatus = 503;
    const logged = world.log.length;
    expect(await page.controller.startRotation(itemId)).toBe(true);
    expect(world.log.length).toBe(logged + 1);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'audit_failed' } });
    expect(world.audit.length).toBe(0);
  });

  it('seals under the current key epoch after a rekey', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world);
    world.ownerRekey([itemId]);
    await page.controller.refresh();
    await page.controller.startRotation(itemId);
    expect(world.audit.at(-1)!.entry.kid).toBe('e2');
    expect(world.auditEvents().at(-1)).toMatchObject({ action: 'rotation_started' });
  });
});

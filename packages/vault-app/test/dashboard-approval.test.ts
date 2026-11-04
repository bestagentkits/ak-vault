// @vitest-environment happy-dom
/**
 * Remote access approvals in the dashboard: the `#approval=` fragment survives
 * sign-in, the request opens only after the requester's signature verifies against
 * the verified membership, and each button sends one decision signed by this
 * browser's own device key that the requesting device can verify. The sealed
 * subject never travels in the clear.
 */
import { describe, expect, it } from 'vitest';
import { createDeviceKeys, randomId, verifyApprovalDecision, type ApprovalSubject } from '@ak-vault/protocol';
import { parseApprovalLink } from '../src/sync/approval-request.js';
import { ttlLabel } from '../src/ui/approval-view.js';
import { ACCOUNT, FakeWorld, ORIGIN } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, settle, type Page } from './helpers/dashboard-page.js';

const SECRET = 'billing-entry-7c1e';
const SUBJECT: ApprovalSubject = {
  secret: SECRET,
  agent: 'claude-code',
  fingerprint: `sha256:${'ab'.repeat(32)}`,
  project: 'github.com/acme/billing',
  reason: 'run the staging smoke test',
  max_ttl_s: 3600,
};

async function openApprovalPage(world: FakeWorld, requestId: string): Promise<{ b: Browser; page: Page; linkPage: Page }> {
  const b = new Browser(world);
  await b.enroll();
  const linkPage = await b.load(world.approvalUrl(requestId));
  const page = await b.signIn();
  await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'approval', busy: false }));
  return { b, page, linkPage };
}

function approverOf(world: FakeWorld, page: Page) {
  const s = page.controller.current();
  if (!('deviceId' in s) || typeof s.deviceId !== 'string') throw new Error('no device');
  return world.state().devices.find((d) => d.device_id === s.deviceId)!;
}

describe('approval link', () => {
  it('parses only an exact fragment of two canonical 16-byte IDs', () => {
    const a = randomId();
    const v = randomId();
    expect(parseApprovalLink(`#approval=${a}&vault=${v}`)).toEqual({ requestId: a, vaultId: v });
    for (const bad of ['', `#vault=${v}&approval=${a}`, `#approval=${a}`, `#approval=${a}&vault=${v}&x=1`, `#write=${a}&vault=${v}`, '#approval=<b>&vault=x']) {
      expect(parseApprovalLink(bad), bad).toBeNull();
    }
  });

  it('labels the allow-for-a-while choices', () => {
    expect([900, 3600, 28_800].map(ttlLabel)).toEqual(['15 minutes', '1 hour', '8 hours']);
  });
});

describe('approval screen', () => {
  it('clears the fragment, survives sign-in, shows the verified subject and allows once', async () => {
    const world = new FakeWorld();
    const wire = world.seedApproval(world.owner, SUBJECT);
    const { b, page, linkPage } = await openApprovalPage(world, wire.request_id);
    expect(linkPage.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(linkPage.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'approval_signin' } });
    expect(b.pending.value).toBeNull();
    expect(page.controller.current()).toMatchObject({ kind: 'approval', open: true, request: { secret: SECRET, agent: 'claude-code', ttlChoices: [900, 3600] } });
    expect(byTestId(page.root, 'approval-secret').textContent).toBe(SECRET);
    expect(byTestId(page.root, 'approval-reason').textContent).toBe(SUBJECT.reason);
    // max_ttl_s is one hour, so the eight-hour choice is not offered.
    expect(allByTestId(page.root, 'approval-allow-28800')).toHaveLength(0);
    // The subject crossed the wire only sealed.
    for (const e of world.exchanges) expect(`${e.url} ${e.requestBody} ${e.responseBody}`).not.toContain(SECRET);

    byTestId(page.root, 'approval-allow-once').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'approval', open: false, busy: false, notice: { code: 'approval_allowed' } }));
    const row = world.approvals.get(wire.request_id)!;
    expect(row.state).toBe('allowed');
    // The requesting device verifies the signed answer against the approver's key.
    expect(verifyApprovalDecision(row.decision, wire, { approverSignPub: approverOf(world, page).sign_pub, maxTtlS: SUBJECT.max_ttl_s })).toMatchObject({ decision: 'allow_once' });
  });

  it('allows for a while with the chosen TTL, and denies', async () => {
    const world = new FakeWorld();
    const first = world.seedApproval(world.owner, SUBJECT);
    const { page } = await openApprovalPage(world, first.request_id);
    byTestId(page.root, 'approval-allow-3600').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'approval_allowed' } }));
    expect(world.approvals.get(first.request_id)!.decision).toMatchObject({ decision: 'allow_ttl', ttl_s: 3600 });

    const second = world.seedApproval(world.owner, SUBJECT);
    await page.controller.openApprovalLink({ requestId: second.request_id, vaultId: world.vaultId });
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'approval', open: true }));
    byTestId(page.root, 'approval-deny').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'approval_denied' } }));
    expect(world.approvals.get(second.request_id)!.state).toBe('denied');
  });

  it('shows nothing for a request signed by a device outside the vault', async () => {
    const world = new FakeWorld();
    const stranger = createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' });
    const wire = world.seedApproval(stranger, SUBJECT, { account: ACCOUNT });
    const { page } = await openApprovalPage(world, wire.request_id);
    expect(page.controller.current()).toMatchObject({ kind: 'approval', open: false, request: null, notice: { kind: 'error', code: 'approval_unavailable' } });
    expect(page.root.innerHTML).not.toContain(SECRET);
  });

  it('refuses a request already answered elsewhere', async () => {
    const world = new FakeWorld();
    const wire = world.seedApproval(world.owner, SUBJECT);
    const { page } = await openApprovalPage(world, wire.request_id);
    world.approvals.get(wire.request_id)!.state = 'denied';
    byTestId(page.root, 'approval-allow-once').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'approval', notice: { kind: 'error', code: 'approval_unavailable' } }));
    expect(world.approvals.get(wire.request_id)!.decision).toBeNull();
  });

  it('lists pending approvals on the vault screen and opens one', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const wire = world.seedApproval(world.owner, SUBJECT);
    const page = await b.signIn();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', approvals: [wire.request_id] }));
    byTestId(page.root, 'approval-open').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'approval', open: true, request: { secret: SECRET } }));
    byTestId(page.root, 'approval-back').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'vault' }));
  });
});

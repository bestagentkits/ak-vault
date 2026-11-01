// @vitest-environment happy-dom
/**
 * The input form end to end (spec §3.11): the link's fragment, the dispatch away
 * from the dashboard, sign-in with the dashboard client under the form's own
 * pending key, the `input` token checks, the request's state, sealing with the
 * exact AAD, the single `{sealed}` submission and every outcome, and that the
 * typed value never reaches the DOM, the console, an error or any request other
 * than its seal.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { b64encode, generateInputKeyPair, openInput, randomBytes, randomId, type InputSealContext } from '@ak-vault/protocol';
import { isInputFragment, parseInputLink } from '../src/input/input-link.js';
import { checkInputToken, InputError } from '../src/input/input-api.js';
import { outcomeStep } from '../src/input/input-controller.js';
import { dispatchPage, isInputPage } from '../src/main.js';
import { INPUT_PENDING_KEY, sessionPendingStore } from '../src/oauth/pkce-client.js';
import type { AppConfig } from '../src/config.js';
import { ACCOUNT, ISSUER, ORIGIN, fakeJwt } from './helpers/fake-world.js';
import { FakeInputWorld, INPUT_AUDIENCE, REQUESTING_CLIENT, loadInputPage, signInFromLink, type InputPage } from './helpers/fake-input-world.js';
import { byTestId, settle } from './helpers/dashboard-page.js';

const SENTINEL = 'sentinel-input-value-93c1e07a';
const DASHBOARD_KEY = 'akv-dashboard-signin';

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  window.sessionStorage.clear();
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toContain(SENTINEL);
    s.mockRestore();
  }
});

const ID_A = b64encode(randomBytes(16));
const ID_B = b64encode(randomBytes(16));
const PUB = b64encode(randomBytes(32));

function hash(parts: string[]): string {
  return `#${parts.join('&')}`;
}

function screenOf(page: InputPage) {
  return page.controller.current();
}

function noticeText(page: InputPage): string {
  return byTestId(page.root, 'notice').textContent ?? '';
}

async function typeAndSubmit(page: InputPage, value: string): Promise<HTMLInputElement> {
  const input = byTestId(page.root, 'input-value') as HTMLInputElement;
  input.value = value;
  (input.form as HTMLFormElement).dispatchEvent(new Event('submit', { cancelable: true }));
  expect(input.value).toBe('');
  await settle(() => {
    const s = screenOf(page);
    expect(s.kind === 'closed' || (s.kind === 'form' && !s.busy)).toBe(true);
  });
  return input;
}

function expectNoValueAnywhere(world: FakeInputWorld, page: InputPage): void {
  expect(page.root.innerHTML).not.toContain(SENTINEL);
  expect(page.root.textContent).not.toContain(SENTINEL);
  for (const e of world.exchanges) {
    expect(e.requestBody).not.toContain(SENTINEL);
    expect(e.responseBody).not.toContain(SENTINEL);
    expect(e.url).not.toContain(SENTINEL);
  }
  expect(JSON.stringify(window.sessionStorage)).not.toContain(SENTINEL);
  for (let i = 0; i < window.sessionStorage.length; i++) expect(window.sessionStorage.getItem(window.sessionStorage.key(i)!)).not.toContain(SENTINEL);
}

describe('input link parsing', () => {
  it('parses the Worker-built fragment, decoding name and purpose', () => {
    const name = 'db/url & token=1 ü';
    const link = parseInputLink(hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, `n=${encodeURIComponent('DB url & token=1 ü')}`, `p=${encodeURIComponent('Deploy #3 & co')}`]));
    expect(link).toEqual({ requestId: ID_A, vaultId: ID_B, inputPub: PUB, name: 'DB url & token=1 ü', purpose: 'Deploy #3 & co' });
    // A name the dashboard would refuse ("/") is refused here too.
    expect(parseInputLink(hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, `n=${encodeURIComponent(name)}`]))).toBeNull();
  });

  it('accepts a link without a purpose, in any key order', () => {
    expect(parseInputLink(hash([`k=${PUB}`, `n=API_KEY`, `v=${ID_B}`, `r=${ID_A}`]))).toEqual({ requestId: ID_A, vaultId: ID_B, inputPub: PUB, name: 'API_KEY', purpose: null });
  });

  const base = [`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, 'n=API_KEY'];
  const invalid: Record<string, string> = {
    'missing r': hash(base.filter((p) => !p.startsWith('r='))),
    'missing v': hash(base.filter((p) => !p.startsWith('v='))),
    'missing k': hash(base.filter((p) => !p.startsWith('k='))),
    'missing n': hash(base.filter((p) => !p.startsWith('n='))),
    'duplicate r': hash([...base, `r=${ID_A}`]),
    'duplicate n': hash([...base, 'n=OTHER']),
    'duplicate p': hash([...base, 'p=a', 'p=a']),
    'extra key': hash([...base, 'x=1']),
    'extra write key': hash([...base, `write=${ID_A}`]),
    'short key': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${b64encode(randomBytes(31))}`, 'n=API_KEY']),
    'long key': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${b64encode(randomBytes(33))}`, 'n=API_KEY']),
    'padded key': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}=`, 'n=API_KEY']),
    'bad request id': hash([`r=${ID_A.slice(1)}`, `v=${ID_B}`, `k=${PUB}`, 'n=API_KEY']),
    'bad vault id': hash([`r=${ID_A}`, `v=${ID_B}x`, `k=${PUB}`, 'n=API_KEY']),
    'non-b64 id': hash([`r=${'!'.repeat(22)}`, `v=${ID_B}`, `k=${PUB}`, 'n=API_KEY']),
    'empty name': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, 'n=']),
    'empty purpose': hash([...base, 'p=']),
    'oversize purpose': hash([...base, `p=${'a'.repeat(201)}`]),
    'control char in name': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, `n=${encodeURIComponent('A‮B')}`]),
    'bad percent-encoding': hash([`r=${ID_A}`, `v=${ID_B}`, `k=${PUB}`, 'n=%E0%A4%A']),
    'trailing separator': hash([...base, '']),
    'raw equals in value': `${hash(base)}=`,
    'empty fragment': '#',
    'no fragment': '',
  };
  for (const [what, h] of Object.entries(invalid)) {
    it(`refuses a link with ${what}`, () => {
      expect(parseInputLink(h)).toBeNull();
    });
  }

  it('recognises any input-link fragment, valid or not, and never a write link', () => {
    expect(isInputFragment(hash(base))).toBe(true);
    expect(isInputFragment(hash([...base, 'x=1']))).toBe(true);
    expect(isInputFragment('#n=only')).toBe(true);
    expect(isInputFragment('#x=1&k=2')).toBe(true);
    expect(isInputFragment(`#write=${ID_A}&vault=${ID_B}`)).toBe(false);
    expect(isInputFragment('')).toBe(false);
    expect(isInputFragment('#section')).toBe(false);
  });
});

describe('dispatch', () => {
  it('runs the input form for an input fragment or the callback of an input sign-in only', () => {
    const storage = window.sessionStorage;
    expect(isInputPage(new URL(`${ORIGIN}/app/`), storage)).toBe(false);
    expect(isInputPage(new URL(`${ORIGIN}/app/#write=${ID_A}&vault=${ID_B}`), storage)).toBe(false);
    expect(isInputPage(new URL(`${ORIGIN}/app/?code=c&state=s&iss=x`), storage)).toBe(false);
    // A dashboard sign-in pending in this tab keeps its callback on the dashboard.
    storage.setItem(DASHBOARD_KEY, '{}');
    expect(isInputPage(new URL(`${ORIGIN}/app/?code=c&state=s&iss=x`), storage)).toBe(false);
    expect(isInputPage(new URL(`${ORIGIN}/app/${hash([`r=${ID_A}`])}`), storage)).toBe(true);
    storage.setItem(INPUT_PENDING_KEY, '{}');
    expect(isInputPage(new URL(`${ORIGIN}/app/?code=c&state=s&iss=x`), storage)).toBe(true);
    // A pending input sign-in does not take over a plain dashboard load.
    expect(isInputPage(new URL(`${ORIGIN}/app/`), storage)).toBe(false);
  });

  it('a dashboard load removes a pending input sign-in; a callback with its matching state keeps it for the input form', async () => {
    const world = new FakeInputWorld();
    const linkPage = await loadInputPage(world, world.linkUrl());
    linkPage.controller.signIn();
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).not.toBeNull();
    const callback = world.authorize(linkPage.navigated[0]!);

    // The callback (matching state) goes to the input form and leaves the entry for it to read.
    expect(dispatchPage(callback, window.sessionStorage)).toBe('input');
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).not.toBeNull();
    const page = await loadInputPage(world, callback);
    expect(screenOf(page).kind).toBe('form');
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();

    // A plain dashboard load (or a write link) deletes an unfinished one.
    for (const url of [`${ORIGIN}/app/`, `${ORIGIN}/app/#write=${ID_A}&vault=${ID_B}`]) {
      window.sessionStorage.setItem(INPUT_PENDING_KEY, JSON.stringify({ state: 's', verifier: 'v', createdAt: Date.now() }));
      window.sessionStorage.setItem(DASHBOARD_KEY, '{"keep":true}');
      expect(dispatchPage(new URL(url), window.sessionStorage)).toBe('dashboard');
      expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();
      // The dashboard's own pending sign-in is not touched.
      expect(window.sessionStorage.getItem(DASHBOARD_KEY)).toBe('{"keep":true}');
    }
  });
});

describe('input token checks', () => {
  const config: AppConfig = { origin: ORIGIN, issuer: ISSUER, clientId: `${ORIGIN}/app/client.json`, redirectUri: `${ORIGIN}/app/`, resource: `${ORIGIN}/app`, scope: 'vault-app:session' };
  const session = { accessToken: 'x', refreshToken: null, expiresAt: 0, claims: { sub: ACCOUNT, sid: 'grant-1', exp: 0 } };
  const now = Date.now();
  const good = (): Record<string, unknown> => {
    const s = Math.floor(now / 1000);
    return { iss: ISSUER, aud: INPUT_AUDIENCE, sub: ACCOUNT, sid: 'grant-1', session_kind: 'input', jti: randomId(), iat: s, nbf: s, exp: s + 300 };
  };

  it('accepts the token asked for and keeps the earlier expiry', () => {
    const t = checkInputToken(fakeJwt(good()), 60, config, session, now);
    expect(t.expiresAt).toBe(Math.floor(now / 1000) + 60);
  });

  const bad: Record<string, Record<string, unknown>> = {
    'the app audience': { aud: `${ORIGIN}/app` },
    'the sync audience': { aud: ORIGIN },
    'another session kind': { session_kind: 'browser' },
    'no session kind': { session_kind: undefined },
    'another account': { sub: 'acct-mallory' },
    'a device': { did: randomId() },
    'another issuer': { iss: 'https://evil.example.test' },
    'no expiry': { exp: undefined },
  };
  for (const [what, patch] of Object.entries(bad)) {
    it(`refuses a token with ${what}`, () => {
      const claims = { ...good(), ...patch };
      for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
      expect(() => checkInputToken(fakeJwt(claims), 300, config, session, now)).toThrow(InputError);
    });
  }

  it('refuses a token that is not a JWT or has no lifetime', () => {
    expect(() => checkInputToken('opaque', 300, config, session, now)).toThrow(InputError);
    expect(() => checkInputToken(fakeJwt(good()), 0, config, session, now)).toThrow(InputError);
  });

  for (const [what, patch] of Object.entries({ 'wrong aud': { aud: `${ORIGIN}/app` }, 'wrong session_kind': { session_kind: 'browser' }, 'sub mismatch': { sub: 'acct-mallory' }, 'did present': { did: randomId() } })) {
    it(`the page refuses an input token with ${what}, sends nothing to the vault and revokes the grant`, async () => {
      const world = new FakeInputWorld();
      world.knobs.inputClaims = patch;
      const { page } = await signInFromLink(world);
      expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'signin_refused' } });
      expect(world.calls('/input-requests/')).toHaveLength(0);
      await settle(() => expect(world.revoked).toHaveLength(1));
    });
  }
});

describe('input form flow', () => {
  it('shows the request from the link and waits for the person before signing in', async () => {
    const world = new FakeInputWorld();
    const page = await loadInputPage(world, world.linkUrl());
    expect(screenOf(page).kind).toBe('signin');
    expect(byTestId(page.root, 'input-name').textContent).toBe(world.request.name);
    expect(byTestId(page.root, 'input-purpose').textContent).toBe(world.request.purpose);
    // The fragment left the address bar; nothing navigated yet.
    expect(page.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(page.navigated).toEqual([]);
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();
  });

  it('an invalid link shows only that it is invalid and never signs in', async () => {
    const world = new FakeInputWorld();
    const page = await loadInputPage(world, `${ORIGIN}/app/${world.linkHash()}&x=1`);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', summary: null, notice: { code: 'input_link_invalid' } });
    expect(noticeText(page)).toContain('invalid');
    expect(page.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(page.root.querySelector('[data-testid="input-signin"]')).toBeNull();
    expect(world.calls('/oauth/')).toHaveLength(0);
  });

  it('carries the input link across the sign-in under the input key only, and deletes it on the callback', async () => {
    const world = new FakeInputWorld();
    const linkPage = await loadInputPage(world, world.linkUrl());
    byTestId(linkPage.root, 'input-signin').click();
    expect(linkPage.navigated).toHaveLength(1);
    const auth = new URL(linkPage.navigated[0]!);
    expect(auth.searchParams.get('client_id')).toBe(`${ORIGIN}/app/client.json`);
    expect(auth.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/app/`);
    expect(auth.searchParams.get('resource')).toBe(`${ORIGIN}/app`);
    expect(auth.searchParams.get('scope')).toBe('vault-app:session');
    // Nothing from the link rides on the authorization request.
    expect(auth.href).not.toContain(world.request.requestId);
    expect(auth.href).not.toContain(encodeURIComponent(world.request.name));
    expect(window.sessionStorage.getItem(DASHBOARD_KEY)).toBeNull();
    const stored = JSON.parse(window.sessionStorage.getItem(INPUT_PENDING_KEY)!) as Record<string, unknown>;
    expect(stored['inputLink']).toEqual({ requestId: world.request.requestId, vaultId: world.request.vaultId, inputPub: world.inputPub, name: world.request.name, purpose: world.request.purpose });

    const page = await loadInputPage(world, world.authorize(linkPage.navigated[0]!));
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();
    expect(page.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(screenOf(page)).toMatchObject({ kind: 'form', busy: false, request: { name: world.request.name, purpose: world.request.purpose, operation: 'create', clientId: REQUESTING_CLIENT, expiresAt: world.request.expiresAt } });
    expect(byTestId(page.root, 'input-client').textContent).toBe(REQUESTING_CLIENT);
    expect(byTestId(page.root, 'input-operation').textContent).toBe('Create a new secret');
    const field = byTestId(page.root, 'input-value') as HTMLInputElement;
    expect(field.type).toBe('password');
    expect(field.getAttribute('autocomplete')).toBe('off');
    expect(field.getAttribute('spellcheck')).toBe('false');
    // The input token is minted with the app token, no body, no cookies.
    const mint = world.calls('/api/agentkit/vault/input-token');
    expect(mint).toHaveLength(1);
    expect(mint[0]!.method).toBe('POST');
    expect(mint[0]!.requestBody).toBe('');
  });

  it('a stale pending input sign-in is refused', async () => {
    const world = new FakeInputWorld();
    const linkPage = await loadInputPage(world, world.linkUrl());
    linkPage.controller.signIn();
    const stored = JSON.parse(window.sessionStorage.getItem(INPUT_PENDING_KEY)!) as Record<string, unknown>;
    window.sessionStorage.setItem(INPUT_PENDING_KEY, JSON.stringify({ ...stored, createdAt: Date.now() - 11 * 60 * 1000 }));
    const page = await loadInputPage(world, world.authorize(linkPage.navigated[0]!));
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'signin_state_mismatch' } });
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();
  });

  it('a tampered pending link is refused', () => {
    const store = sessionPendingStore(window.sessionStorage, INPUT_PENDING_KEY);
    window.sessionStorage.setItem(INPUT_PENDING_KEY, JSON.stringify({ state: 's', verifier: 'v', createdAt: Date.now(), inputLink: { requestId: ID_A, vaultId: ID_B, inputPub: 'short', name: 'A', purpose: null } }));
    expect(store.take()).toBeNull();
    expect(window.sessionStorage.getItem(INPUT_PENDING_KEY)).toBeNull();
  });

  it('seals with the exact AAD and posts only {sealed}; the field is cleared and the grant revoked', async () => {
    const world = new FakeInputWorld();
    const { page } = await signInFromLink(world);
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_saved' } });
    expect(byTestId(page.root, 'input-receipt').textContent).toBe(`Receipt ${world.request.receipt!.slice(0, 8)}`);
    expect(world.delivered).toEqual([{ value: SENTINEL }]);

    const posts = world.calls('/input-requests/').filter((e) => e.method === 'POST');
    expect(posts).toHaveLength(1);
    const body = JSON.parse(posts[0]!.requestBody) as { sealed: Record<string, unknown> };
    expect(Object.keys(body)).toEqual(['sealed']);
    expect(Object.keys(body.sealed).sort()).toEqual(['alg', 'ct', 'epk', 'n', 'request_id', 'v']);
    expect(posts[0]!.headers['authorization']).toMatch(/^Bearer /);
    expect(posts[0]!.headers['content-type']).toBe('application/json');

    // The AAD binds every context field: the same seal opens only under the recorded one.
    const ctx = world.context();
    expect(openInput(world.key.secretKey, body.sealed, ctx)).toEqual({ value: SENTINEL });
    const changed: Partial<InputSealContext>[] = [{ name: 'other-name' }, { account: 'acct-mallory' }, { device_id: randomId() }, { purpose: null }, { operation: 'replace' }, { expires_at: ctx.expires_at + 1 }, { vault_id: randomId() }];
    for (const patch of changed) expect(() => openInput(world.key.secretKey, body.sealed, { ...ctx, ...patch }), JSON.stringify(Object.keys(patch))).toThrow();
    expect(() => openInput(generateInputKeyPair().secretKey, body.sealed, ctx)).toThrow();

    await settle(() => expect(world.revoked).toHaveLength(1));
    expectNoValueAnywhere(world, page);
  });

  it('seals a request without a purpose with purpose null', async () => {
    const world = new FakeInputWorld({ purpose: null, operation: 'replace' });
    const { page } = await signInFromLink(world);
    expect(page.root.querySelector('[data-testid="input-purpose"]')).toBeNull();
    expect(byTestId(page.root, 'input-operation').textContent).toBe('Replace the value of an existing secret');
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_saved' } });
    expect(world.delivered).toEqual([{ value: SENTINEL }]);
  });

  it('a fragment edited to show another name produces a seal the device cannot open', async () => {
    const world = new FakeInputWorld();
    const linkPage = await loadInputPage(world, world.linkUrl().replace(`n=${world.request.name}`, 'n=innocent-name'));
    linkPage.controller.signIn();
    const page = await loadInputPage(world, world.authorize(linkPage.navigated[0]!));
    expect(byTestId(page.root, 'input-name').textContent).toBe('innocent-name');
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_rejected' } });
    expect(world.delivered).toEqual([]);
  });

  it('refuses an empty value without sending anything', async () => {
    const world = new FakeInputWorld();
    const { page } = await signInFromLink(world);
    await typeAndSubmit(page, '');
    expect(screenOf(page)).toMatchObject({ kind: 'form', notice: { code: 'input_value_empty' } });
    expect(world.calls('/input-requests/').filter((e) => e.method === 'POST')).toHaveLength(0);
  });

  it('refuses a value over the item limit without sending anything', async () => {
    const world = new FakeInputWorld();
    const { page } = await signInFromLink(world);
    await typeAndSubmit(page, 'x'.repeat(65_537));
    expect(screenOf(page)).toMatchObject({ kind: 'form', notice: { code: 'value_too_large' } });
    // Within the UTF-16 limit but over the sealed plaintext limit in UTF-8 bytes.
    await typeAndSubmit(page, 'é'.repeat(40_000));
    expect(screenOf(page)).toMatchObject({ kind: 'form', notice: { code: 'value_too_large' } });
    expect(world.calls('/input-requests/').filter((e) => e.method === 'POST')).toHaveLength(0);
  });

  const states: [string, string][] = [
    ['submitted', 'input_submitted'],
    ['completed', 'input_completed'],
    ['expired', 'input_expired'],
    ['failed', 'input_failed'],
    ['conflict', 'input_conflict'],
    ['cancelled', 'input_cancelled'],
  ];
  for (const [state, code] of states) {
    it(`a request in state ${state} shows no form and revokes the grant`, async () => {
      const world = new FakeInputWorld({ state });
      const { page } = await signInFromLink(world);
      expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code } });
      expect(page.root.querySelector('[data-testid="input-value"]')).toBeNull();
      await settle(() => expect(world.revoked).toHaveLength(1));
    });
  }

  it('a request past its expiry by this clock shows no form', async () => {
    const world = new FakeInputWorld({ expiresAt: Date.now() - 1000 });
    const { page } = await signInFromLink(world);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_expired' } });
  });

  it('a request of another account (404) says it does not exist or is not yours', async () => {
    const world = new FakeInputWorld();
    world.request.account = 'acct-bob';
    const { page } = await signInFromLink(world);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_not_found' } });
    expect(noticeText(page)).toContain('not yours');
  });

  it('a request answer for another request ID is refused', async () => {
    const world = new FakeInputWorld();
    world.knobs.getRequestId = randomId();
    const { page } = await signInFromLink(world);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_invalid_response' } });
  });

  for (const [status, code] of [[404, 'input_unavailable'], [401, 'signin_refused'], [403, 'signin_refused'], [500, 'server'], [503, 'server']] as const) {
    it(`an input-token answer ${status} shows ${code}`, async () => {
      const world = new FakeInputWorld();
      world.knobs.inputTokenStatus = status;
      const { page } = await signInFromLink(world);
      expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code } });
      expect(world.calls('/input-requests/')).toHaveLength(0);
    });
  }

  it('a server error while loading can be retried with the same sign-in', async () => {
    const world = new FakeInputWorld();
    world.knobs.inputTokenStatus = 503;
    const { page } = await signInFromLink(world);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'server' }, retry: true });
    world.knobs.inputTokenStatus = null;
    byTestId(page.root, 'input-retry').click();
    await settle(() => expect(screenOf(page).kind).toBe('form'));
  });

  it('a lapsed input token is minted again once', async () => {
    const world = new FakeInputWorld();
    world.knobs.reject401 = 1;
    const { page } = await signInFromLink(world);
    expect(screenOf(page).kind).toBe('form');
    expect(world.calls('/api/agentkit/vault/input-token')).toHaveLength(2);
    world.knobs.reject401 = 2;
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'signin_refused' } });
  });

  it('an offline device keeps the request open: the person types the value again and it stores', async () => {
    const world = new FakeInputWorld();
    world.knobs.postAnswers.push(FakeInputWorld.error(503, 'device_offline', 'pending_user', { 'Retry-After': '5' }));
    const { page } = await signInFromLink(world);
    const field = await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'form', busy: false, notice: { code: 'input_device_offline' } });
    expect(noticeText(page)).toContain('offline');
    expect(field.value).toBe('');
    expect((byTestId(page.root, 'input-value') as HTMLInputElement).value).toBe('');
    expect(world.revoked).toHaveLength(0);
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_saved' } });
    expect(world.delivered).toEqual([{ value: SENTINEL }]);
    await settle(() => expect(world.revoked).toHaveLength(1));
    expectNoValueAnywhere(world, page);
  });

  const outcomes: [string, Response, string, boolean][] = [
    ['429 busy', FakeInputWorld.error(429, 'rate_limited', 'pending_user'), 'input_device_busy', false],
    ['400 undeliverable', FakeInputWorld.error(400, 'bad_request', 'pending_user'), 'input_undeliverable', false],
    ['400 failed', FakeInputWorld.error(400, 'bad_request', 'failed'), 'input_rejected', true],
    ['400 unsupported_version before the claim', FakeInputWorld.error(400, 'unsupported_version', null), 'input_undeliverable', false],
    ['400 bad_request before the claim', FakeInputWorld.error(400, 'bad_request', null), 'input_undeliverable', false],
    ['504 timeout', FakeInputWorld.error(504, 'device_timeout', 'failed'), 'input_timeout', true],
    ['409 already submitted', FakeInputWorld.error(409, 'conflict', 'submitted'), 'input_closed', true],
    ['409 conflict', FakeInputWorld.error(409, 'conflict', 'conflict'), 'input_conflict', true],
    ['403 refused', FakeInputWorld.error(403, 'forbidden', 'failed'), 'input_refused', true],
    ['410 expired', FakeInputWorld.error(410, 'expired', 'expired'), 'input_expired', true],
    ['500 failed', FakeInputWorld.error(500, 'internal', 'failed'), 'input_failed', true],
    ['503 lookup', FakeInputWorld.error(503, 'internal', null), 'server', false],
    ['200 without a receipt', new Response(JSON.stringify({ status: 'stored' }), { status: 200 }), 'input_failed', true],
  ];
  for (const [what, answer, code, terminal] of outcomes) {
    it(`POST ${what} shows ${code}${terminal ? ' and revokes the grant' : ' and keeps the form'}`, async () => {
      const world = new FakeInputWorld();
      world.knobs.postAnswers.push(answer);
      const { page } = await signInFromLink(world);
      await typeAndSubmit(page, SENTINEL);
      expect(screenOf(page)).toMatchObject({ kind: terminal ? 'closed' : 'form', notice: { kind: 'error', code } });
      if (terminal) await settle(() => expect(world.revoked).toHaveLength(1));
      else expect(world.revoked).toHaveLength(0);
      expectNoValueAnywhere(world, page);
    });
  }

  it('the name, purpose and input key from the fragment never reach a server', async () => {
    const world = new FakeInputWorld({ name: 'SENTINEL_NAME_7f3a', purpose: 'SENTINEL_PURPOSE_51c9' });
    const { page } = await signInFromLink(world);
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'closed', notice: { code: 'input_saved' } });
    const secrets = [world.request.name, world.request.purpose!, world.inputPub];
    expect(world.exchanges.length).toBeGreaterThan(5);
    for (const e of world.exchanges) {
      for (const s of secrets) {
        expect(e.url, e.url).not.toContain(s);
        expect(e.requestBody, e.url).not.toContain(s);
        for (const v of Object.values(e.headers)) expect(v).not.toContain(s);
      }
    }
  });

  it('a network failure on submit keeps the form', async () => {
    const world = new FakeInputWorld();
    const { page } = await signInFromLink(world);
    world.knobs.offline = true;
    await typeAndSubmit(page, SENTINEL);
    expect(screenOf(page)).toMatchObject({ kind: 'form', notice: { code: 'network' } });
  });

  it('leaving the page revokes the grant with keepalive', async () => {
    const world = new FakeInputWorld();
    const { page } = await signInFromLink(world);
    page.controller.revokeOnExit();
    await settle(() => expect(world.exchanges.find((e) => e.url.endsWith('/oauth/revoke'))?.keepalive).toBe(true));
    expect(world.revoked).toHaveLength(1);
  });
});

describe('outcome mapping', () => {
  it('maps a stored answer to the receipt and an unknown 4xx to failed', () => {
    expect(outcomeStep({ kind: 'stored', receipt: 'r1' })).toEqual({ screen: 'closed', notice: { kind: 'info', code: 'input_saved' }, receipt: 'r1' });
    expect(outcomeStep({ kind: 'error', status: 418, code: 'unknown', state: null })).toEqual({ screen: 'closed', notice: { kind: 'error', code: 'input_failed' } });
  });
});

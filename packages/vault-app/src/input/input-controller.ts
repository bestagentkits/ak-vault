/**
 * The input form (spec §3.11, ADR 0004): an account with no enrolled browser
 * device types a secret value that one of its online devices asked for. The page
 * signs in with the dashboard's OAuth client, trades the app token for a
 * short-lived `input` session token, fetches the request's state, seals the value
 * to the device's one-time input key with the request bound in the AAD, and posts
 * the seal once. It holds no device key and keeps nothing at rest but the pending
 * sign-in across the redirect. Tokens live in memory only; a terminal outcome or
 * leaving the page revokes the sign-in grant, which also ends the `input` token.
 */
import { sealInput, type InputSealContext } from '@ak-vault/protocol';
import { appErrorCode, type AppErrorCode } from '../app-error.js';
import { loadAppConfig, type AppConfig } from '../config.js';
import {
  beginSignIn,
  completeSignIn,
  discoverAuthServer,
  isAuthorizationResponse,
  refreshSession,
  revokeSession,
  type AuthServerMetadata,
  type OAuthSession,
  type PendingStore,
} from '../oauth/pkce-client.js';
import { validItemValue } from '../sync/item-names.js';
import {
  fetchInputRequest,
  InputError,
  mintInputToken,
  submitInput,
  type InputRequestState,
  type InputToken,
  type SubmitOutcome,
} from './input-api.js';
import { parseInputLink, type InputLink } from './input-link.js';

export type InputNoticeCode =
  | 'input_link_invalid'
  | 'input_signin'
  | 'input_unavailable'
  | 'input_not_found'
  | 'input_invalid_response'
  | 'input_value_empty'
  | 'input_saved'
  | 'input_submitted'
  | 'input_completed'
  | 'input_expired'
  | 'input_failed'
  | 'input_conflict'
  | 'input_closed'
  | 'input_cancelled'
  | 'input_device_offline'
  | 'input_device_busy'
  | 'input_undeliverable'
  | 'input_rejected'
  | 'input_timeout'
  | 'input_refused';

export interface InputNotice {
  kind: 'info' | 'error';
  code: AppErrorCode | InputNoticeCode;
}

/** What the link says the request is for, as chosen by the requesting AI client. */
export interface InputSummary {
  name: string;
  purpose: string | null;
}

/** What the form shows about the request. Never a value. */
export interface InputRequestView extends InputSummary {
  operation: 'create' | 'replace';
  clientId: string;
  /** Unix ms. */
  expiresAt: number;
}

export type InputScreen =
  | { kind: 'loading' }
  | { kind: 'signin'; summary: InputSummary; notice: InputNotice | null }
  | { kind: 'form'; request: InputRequestView; busy: boolean; notice: InputNotice | null }
  /** Nothing more to do on this page; `retry` reloads the request after a network or server error. */
  | { kind: 'closed'; summary: InputSummary | null; notice: InputNotice; receipt: string | null; retry: boolean };

export interface InputControllerDeps {
  origin: string;
  fetchFn: typeof fetch;
  /** The input form's own pending sign-in (never the dashboard's). */
  pending: PendingStore;
  /** Leave the page for the authorization server. */
  navigate(url: string): void;
  /** Replace the current URL without a navigation (drops the fragment, code and state). */
  replaceUrl(url: string): void;
  now?: () => number;
}

/** Refresh a token this long before it expires (seconds). */
const EXPIRY_MARGIN_S = 30;

/** The request state the GET answered, as the notice the closed screen shows. */
const STATE_NOTICE: Record<string, InputNoticeCode> = {
  submitted: 'input_submitted',
  completed: 'input_completed',
  expired: 'input_expired',
  failed: 'input_failed',
  conflict: 'input_conflict',
  cancelled: 'input_cancelled',
};

type Step = { screen: 'form'; notice: InputNotice } | { screen: 'closed'; notice: InputNotice; receipt?: string };

/** Map a POST outcome to what the page does next (spec §3.11 outcome table). */
export function outcomeStep(outcome: SubmitOutcome): Step {
  if (outcome.kind === 'stored') return { screen: 'closed', notice: { kind: 'info', code: 'input_saved' }, receipt: outcome.receipt };
  const { status, code, state } = outcome;
  const closed = (c: InputNoticeCode): Step => ({ screen: 'closed', notice: { kind: 'error', code: c } });
  const retry = (c: AppErrorCode | InputNoticeCode): Step => ({ screen: 'form', notice: { kind: 'error', code: c } });
  if (status === 503 && code === 'device_offline') return retry('input_device_offline');
  if (status === 429) return retry('input_device_busy');
  // A 400 without a state was refused before the claim (body shape, version): the request is still open.
  if (status === 400) return state === 'pending_user' || state === null ? retry('input_undeliverable') : closed('input_rejected');
  if (status === 504) return closed('input_timeout');
  if (status === 409) return closed(state === 'conflict' ? 'input_conflict' : 'input_closed');
  if (status === 403) return closed('input_refused');
  if (status === 404) return closed('input_not_found');
  if (status === 410) return closed('input_expired');
  if (status === 503) return retry('server');
  return closed('input_failed');
}

export class InputController {
  private screen: InputScreen = { kind: 'loading' };
  private readonly listeners = new Set<(s: InputScreen) => void>();
  private config: AppConfig | null = null;
  private as: AuthServerMetadata | null = null;
  private session: OAuthSession | null = null;
  private token: InputToken | null = null;
  private link: InputLink | null = null;
  private request: InputRequestState | null = null;
  private readonly now: () => number;

  constructor(private readonly deps: InputControllerDeps) {
    this.now = deps.now ?? Date.now;
  }

  subscribe(fn: (s: InputScreen) => void): () => void {
    this.listeners.add(fn);
    fn(this.screen);
    return () => this.listeners.delete(fn);
  }

  current(): InputScreen {
    return this.screen;
  }

  private show(screen: InputScreen): void {
    this.screen = screen;
    for (const fn of this.listeners) fn(screen);
  }

  private summary(): InputSummary | null {
    return this.link ? { name: this.link.name, purpose: this.link.purpose } : null;
  }

  private close(notice: InputNotice, opts: { receipt?: string; retry?: boolean } = {}): void {
    this.show({ kind: 'closed', summary: this.summary(), notice, receipt: opts.receipt ?? null, retry: opts.retry === true });
  }

  /** Start: read the link (or finish the sign-in it started) and continue to the form. */
  async boot(url: URL): Promise<void> {
    const callback = isAuthorizationResponse(url);
    try {
      this.config = await loadAppConfig(this.deps.fetchFn, this.deps.origin);
    } catch (err) {
      // The fragment never stays in the address bar, whatever happens next.
      this.deps.replaceUrl(`${this.deps.origin}/app/`);
      this.close({ kind: 'error', code: appErrorCode(err, 'config_invalid') });
      return;
    }
    // The link, code and state leave the address bar and history before anything else runs.
    this.deps.replaceUrl(this.config.redirectUri);
    if (!callback) {
      // A fresh link replaces any sign-in this tab started for an earlier one.
      this.deps.pending.take();
      this.link = parseInputLink(url.hash);
      if (!this.link) {
        this.close({ kind: 'error', code: 'input_link_invalid' });
        return;
      }
    }
    try {
      this.as = await discoverAuthServer(this.deps.fetchFn, this.config.issuer);
    } catch (err) {
      if (callback) this.deps.pending.take();
      this.close({ kind: 'error', code: appErrorCode(err, 'config_invalid') });
      return;
    }
    if (!callback) {
      this.show({ kind: 'signin', summary: this.summary()!, notice: { kind: 'info', code: 'input_signin' } });
      return;
    }
    try {
      const done = await completeSignIn(url, { config: this.config, as: this.as, store: this.deps.pending, fetchFn: this.deps.fetchFn, now: this.now() });
      this.session = done.session;
      this.link = done.inputLink;
    } catch (err) {
      this.close({ kind: 'error', code: appErrorCode(err, 'signin_refused') });
      return;
    }
    if (!this.link) {
      // A sign-in that carried no input link is not this page's to continue.
      await this.dropSession(false);
      this.close({ kind: 'error', code: 'input_link_invalid' });
      return;
    }
    await this.load();
  }

  /** Leave for the authorization server; nothing navigates until the person asks. */
  signIn(): void {
    if (!this.config || !this.as || !this.link || this.screen.kind !== 'signin') return;
    this.deps.navigate(beginSignIn(this.config, this.as, this.deps.pending, this.now(), null, this.link));
  }

  /** After a network or server error while loading: try again with the same sign-in. */
  async retryLoad(): Promise<void> {
    if (this.screen.kind !== 'closed' || !this.screen.retry || !this.session) return;
    this.show({ kind: 'loading' });
    await this.load();
  }

  private async getToken(fresh: boolean): Promise<InputToken> {
    const nowS = Math.floor(this.now() / 1000);
    if (!fresh && this.token && this.token.expiresAt - EXPIRY_MARGIN_S > nowS) return this.token;
    if (!this.session || !this.config || !this.as) throw new InputError('signin_refused');
    if (this.session.expiresAt - EXPIRY_MARGIN_S <= nowS) {
      this.session = await refreshSession(this.session, { config: this.config, as: this.as, fetchFn: this.deps.fetchFn, now: this.now() });
    }
    this.token = await mintInputToken({ config: this.config, session: this.session, fetchFn: this.deps.fetchFn, now: this.now() });
    return this.token;
  }

  /** Run `call` with the `input` token; a 401 mints a fresh token once and tries again. */
  private async withToken<T>(call: (token: InputToken) => Promise<T>): Promise<T> {
    try {
      return await call(await this.getToken(false));
    } catch (err) {
      if (!(err instanceof InputError) || err.code !== 'input_token_expired') throw err;
    }
    try {
      return await call(await this.getToken(true));
    } catch (err) {
      throw err instanceof InputError && err.code === 'input_token_expired' ? new InputError('signin_refused') : err;
    }
  }

  private errorCodeOf(err: unknown): AppErrorCode | InputNoticeCode {
    if (!(err instanceof InputError)) return appErrorCode(err, 'server');
    return err.code === 'input_token_expired' ? 'signin_refused' : err.code;
  }

  /** Mint the `input` token and fetch the request; open the form only for an open, unexpired request. */
  private async load(): Promise<void> {
    const link = this.link;
    const config = this.config;
    if (!link || !config) return;
    let request: InputRequestState;
    try {
      request = await this.withToken((token) => fetchInputRequest(this.deps.fetchFn, config, link, token));
    } catch (err) {
      const code = this.errorCodeOf(err);
      if (code === 'network' || code === 'server') {
        this.close({ kind: 'error', code }, { retry: true });
        return;
      }
      await this.finish({ kind: 'error', code });
      return;
    }
    if (request.state !== 'pending_user') {
      await this.finish({ kind: request.state === 'completed' ? 'info' : 'error', code: STATE_NOTICE[request.state] ?? 'input_closed' });
      return;
    }
    if (request.expiresAt <= this.now()) {
      await this.finish({ kind: 'error', code: 'input_expired' });
      return;
    }
    this.request = request;
    this.showForm(false, null);
  }

  private showForm(busy: boolean, notice: InputNotice | null): void {
    const r = this.request!;
    const l = this.link!;
    this.show({
      kind: 'form', busy, notice,
      request: { name: l.name, purpose: l.purpose, operation: r.operation, clientId: r.clientId, expiresAt: r.expiresAt },
    });
  }

  /**
   * Seal `value` to the device's input key and submit it once. The caller has
   * already cleared the field; this drops its own reference right after sealing.
   * The value is never stored, logged, rendered or put in an error.
   */
  async submit(value: string): Promise<void> {
    const link = this.link;
    const request = this.request;
    const config = this.config;
    const session = this.session;
    if (!link || !request || !config || !session || this.screen.kind !== 'form' || this.screen.busy) return;
    if (value === '') {
      this.showForm(false, { kind: 'error', code: 'input_value_empty' });
      return;
    }
    if (!validItemValue(value)) {
      this.showForm(false, { kind: 'error', code: 'value_too_large' });
      return;
    }
    if (request.expiresAt <= this.now()) {
      await this.finish({ kind: 'error', code: 'input_expired' });
      return;
    }
    const ctx: InputSealContext = {
      request_id: link.requestId,
      vault_id: link.vaultId,
      account: session.claims.sub,
      device_id: request.deviceId,
      name: link.name,
      purpose: link.purpose,
      operation: request.operation,
      expires_at: request.expiresAt,
    };
    let sealed;
    try {
      sealed = sealInput(link.inputPub, ctx, { value });
    } catch {
      // The only payload refusal left is a plaintext over the AEAD limit (UTF-8 bytes).
      this.showForm(false, { kind: 'error', code: 'value_too_large' });
      return;
    } finally {
      value = '';
    }
    this.showForm(true, null);
    let outcome: SubmitOutcome;
    try {
      outcome = await this.withToken((token) => submitInput(this.deps.fetchFn, config, link, token, sealed));
    } catch (err) {
      const code = this.errorCodeOf(err);
      if (code === 'network' || code === 'server') this.showForm(false, { kind: 'error', code });
      else await this.finish({ kind: 'error', code });
      return;
    }
    const step = outcomeStep(outcome);
    if (step.screen === 'form') this.showForm(false, step.notice);
    else await this.finish(step.notice, step.receipt);
  }

  /** A terminal outcome: show it and revoke the sign-in grant (which ends the `input` token too). */
  private async finish(notice: InputNotice, receipt?: string): Promise<void> {
    this.close(notice, receipt === undefined ? {} : { receipt });
    await this.dropSession(false);
  }

  /** Page is going away: revoke with keepalive, without waiting. */
  revokeOnExit(): void {
    void this.dropSession(true);
  }

  private async dropSession(keepalive: boolean): Promise<void> {
    const session = this.session;
    this.session = null;
    this.token = null;
    this.request = null;
    if (session && this.config && this.as) await revokeSession(session, { config: this.config, as: this.as, fetchFn: this.deps.fetchFn, keepalive });
  }
}

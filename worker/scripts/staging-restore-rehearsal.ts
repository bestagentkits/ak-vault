/**
 * Backup/restore rehearsal against the deployed STAGING Worker: a synthetic
 * two-device vault, a recorded bookmark, a real point-in-time restore through the
 * operator route, client reconciliation checks, a forked history after the
 * restore, and the undo. Runbook: "Durable Object backup and restore".
 *
 *   AK_STAGING_SESSION_TOKEN_PATH=<ak staging CLI session token file> \
 *   AKV_OPERATOR_SECRET_PATH=<file holding staging's VAULT_OPERATOR_SECRET> \
 *     tsx scripts/staging-restore-rehearsal.ts [https://vault-staging.agentkit.best]
 *
 * The Worker URL may be omitted; any other origin than staging is refused.
 * Optional AK_STAGING_WEB_ORIGIN and AK_STAGING_SMOKE_STATE_PATH as for the smoke
 * (`scripts/staging-smoke.ts`); the two smoke devices are reused.
 *
 * Each client verifies every pull the way spec §5/§6 require: the membership
 * chain, the whole change log (`verifyChangeLog`), the state digest and change-log
 * head at every position, and `checkRollback` against its highest witnessed
 * checkpoint, plus the digest and head at the witnessed position, so a history
 * that was cut back and then grew past the witnessed `log_seq` is still caught.
 *
 * Prints step names, HTTP statuses, stable error codes, log positions and the
 * first 8 characters of bookmarks: never tokens, proofs, keys, the operator
 * secret or record contents. Exits non-zero when any expectation fails.
 */
import {
  applyRecord,
  b64encode,
  buildGenesisEvent,
  buildProof,
  checkRollback,
  computeStateDigest,
  createDeviceKeys,
  isAkvError,
  LOG_START,
  nextLogHead,
  nextMembershipEvent,
  randomBytes,
  randomId,
  recordDigest,
  sealItem,
  signCheckpoint,
  signKeyPairFromSeed,
  signRecord,
  utf8Encode,
  verifyChangeLog,
  verifyMembershipChain,
  wrapToDevice,
  wrapsDigest,
  type Checkpoint,
  type ChangeLogCursor,
  type DeviceKeys,
  type ItemState,
  type JsonObject,
  type MembershipState,
} from '@ak-vault/protocol';
import { readOperatorSecret, signOperatorRequest } from './operator-restore.js';
import { DEFAULT_AK_WEB_ORIGIN, fail, parseSecureOrigin, readCliSession, reportSmokeFailure, vaultTokenSource } from './staging-smoke-ak-web-token.js';
import { DEFAULT_STATE_PATH, loadDeviceSecrets, type DeviceSecrets } from './staging-smoke-device-state.js';

async function main(): Promise<void> {
  const AUDIENCE = 'https://vault-staging.agentkit.best';
  const base = parseSecureOrigin(process.argv[2] ?? AUDIENCE, 'the Worker URL');
  // Staging only: the one origin this rehearsal may touch.
  if (base !== AUDIENCE) fail('this rehearsal runs only against the staging Worker');
  const akWebOrigin = parseSecureOrigin(process.env['AK_STAGING_WEB_ORIGIN'] || DEFAULT_AK_WEB_ORIGIN, 'AK_STAGING_WEB_ORIGIN');
  const session = readCliSession(process.env['AK_STAGING_SESSION_TOKEN_PATH']);
  const operatorSecret = readOperatorSecret(process.env['AKV_OPERATOR_SECRET_PATH']);
  const secrets = loadDeviceSecrets(process.env['AK_STAGING_SMOKE_STATE_PATH'] || DEFAULT_STATE_PATH, session.userId, ['owner', 'laptop']);
  const tokenFor = vaultTokenSource({ akWebOrigin, audience: AUDIENCE, session });

  const started = Date.now();
  function say(line: string): void {
    process.stdout.write(`${new Date().toISOString().slice(11, 19)} +${((Date.now() - started) / 1000).toFixed(1)}s ${line}\n`);
  }
  const short = (bookmark: string) => `${bookmark.slice(0, 8)}…`;

  interface Result {
    status: number;
    json: Record<string, unknown> | null;
  }

  async function http(path: string, init: RequestInit): Promise<Result> {
    let res: Response;
    try {
      res = await fetch(`${base}${path}`, { ...init, redirect: 'error', signal: AbortSignal.timeout(20_000) });
    } catch {
      return fail(`${init.method ?? 'GET'} ${path.replace(/[A-Za-z0-9_-]{22}/g, ':id')} network error`);
    }
    const text = await res.text();
    let json: Record<string, unknown> | null = null;
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json };
  }

  const codeOf = (r: Result) => (r.json?.['error'] as { code?: string } | undefined)?.code;

  function expectStatus(step: string, res: Result, status: number, code?: string): void {
    const got = codeOf(res);
    if (res.status !== status || (code && got !== code)) fail(`${step}: expected ${status}${code ? ` ${code}` : ''}, got ${res.status}${got ? ` ${got}` : ''}`);
    say(`ok   ${step} (${res.status}${got ? ` ${got}` : ''})`);
  }

  /** A replay is refused by compare-and-swap (409), or by the ±60 s window (401) once it is older. */
  function expectReplayRefused(step: string, res: Result): void {
    const code = codeOf(res);
    if (!((res.status === 409 && code === 'conflict') || (res.status === 401 && code === 'unauthorized'))) fail(`${step}: expected a refusal, got ${res.status} ${code ?? ''}`);
    say(`ok   ${step} is refused (${res.status} ${code}${res.status === 401 ? ', outside the time window' : ', compare-and-swap'})`);
  }

  // ---- operator -----------------------------------------------------------------

  async function operator(body: string): Promise<Result> {
    return http('/internal/v1/operator', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  }

  async function currentBookmark(vaultId: string): Promise<string> {
    const res = await operator(signOperatorRequest(operatorSecret, base, { action: 'bookmark', vault_id: vaultId, at_ms: null }));
    if (res.status !== 200 || typeof res.json?.['bookmark'] !== 'string') fail(`operator bookmark: ${res.status} ${codeOf(res) ?? ''}`);
    return res.json['bookmark'] as string;
  }

  // ---- synthetic devices and vault ------------------------------------------------

  interface Device {
    label: string;
    keys: DeviceKeys;
    secrets: DeviceSecrets;
  }

  const ownerToken = await tokenFor('owner', (secrets['owner'] as DeviceSecrets).signSeed);
  const account = ownerToken.sub;
  if (account !== session.userId) fail('ak-web minted a token for a different account than the session');

  function device(label: string): Device {
    const s = secrets[label] as DeviceSecrets;
    return { label, secrets: s, keys: createDeviceKeys({ account, role: 'owner', kind: 'human', signSeed: s.signSeed, kxSecret: s.kxSecret }) };
  }

  const vaultId = randomId();
  const v = `/v1/vaults/${vaultId}`;
  const vk = randomBytes(32);

  async function api(dev: Device, method: string, path: string, body?: unknown): Promise<Result> {
    const bytes = body === undefined ? new Uint8Array() : utf8Encode(JSON.stringify(body));
    const { token } = await tokenFor(dev.label, dev.secrets.signSeed);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      'AKV-Proof': buildProof({ htm: method, htu: `${base}${path}`, ts: Date.now(), token, body: bytes, secretKey: dev.keys.signSecret }),
    };
    if (method !== 'GET') headers['Idempotency-Key'] = randomId();
    if (bytes.length > 0) headers['Content-Type'] = 'application/json';
    return http(path, { method, headers, ...(method === 'GET' ? {} : { body: new Uint8Array(bytes) }) });
  }

  function record(dev: Device, itemId: string, baseRevision: number, value: string) {
    const author = dev.keys.record.device_id;
    const payload = { name: 'RESTORE_REHEARSAL_SYNTHETIC', value, meta: {}, sensitivity: 'normal' as const };
    const env = sealItem({ vk, vault_id: vaultId, item_id: itemId, base_revision: baseRevision, key_epoch: 1, author, tombstone: false, payload });
    return signRecord({ vault_id: vaultId, item_id: itemId, base_revision: baseRevision, key_epoch: 1, tombstone: false, author, ts: Date.now(), resolves: [], env }, dev.keys.signSecret);
  }

  async function write(dev: Device, itemId: string, baseRevision: number, value: string, step: string): Promise<void> {
    expectStatus(step, await api(dev, 'PUT', `${v}/items/${itemId}`, record(dev, itemId, baseRevision, value)), 200);
  }

  // ---- client model: verify a full pull and keep the highest witnessed checkpoint ---

  interface Witness {
    checkpoint: Checkpoint;
    /** Change-log head this client computed at the checkpoint's position. */
    logHead: string;
  }

  interface PullView {
    state: MembershipState;
    logSeq: number;
    /** Computed per position n (index n): change-log head and state digest. */
    heads: string[];
    digests: string[];
    serverHead: string;
  }

  class Client {
    witness: Witness | null = null;
    constructor(readonly dev: Device) {}

    /** Full verified pull. Throws AkvError (`rollback`, …) on a refused state. */
    async pull(): Promise<PullView> {
      const m = await api(this.dev, 'GET', `${v}/membership?from=0`);
      if (m.status !== 200) fail(`${this.dev.label} membership pull: ${m.status} ${codeOf(m) ?? ''}`);
      if (m.json?.['has_more']) fail('membership did not fit one page');
      const state = verifyMembershipChain(m.json?.['events'] as unknown[]);

      let cursor: ChangeLogCursor = LOG_START;
      const heads = [LOG_START.log_head];
      const digests = [computeStateDigest([])];
      const items = new Map<string, ItemState>();
      let serverHead = '';
      for (;;) {
        const res = await api(this.dev, 'GET', `${v}/changes?cursor=${cursor.log_seq}`);
        if (res.status !== 200) fail(`${this.dev.label} changes pull: ${res.status} ${codeOf(res) ?? ''}`);
        const page = res.json as { changes: { log_seq: number; conflict_id: string | null; record: unknown }[]; has_more: boolean; head: { log_head: string } };
        const entries = page.changes.map(({ log_seq, conflict_id, record: r }) => ({ log_seq, conflict_id, record: r }));
        const verified = verifyChangeLog(entries, state, { from: cursor, complete: !page.has_more, keptHeads: new Map(heads.map((h, i) => [i, h])) });
        verified.records.forEach((r, i) => {
          const entry = entries[i]!;
          heads.push(nextLogHead(heads[heads.length - 1]!, entry.log_seq, entry.conflict_id, recordDigest(r)));
          const applied = applyRecord(items.get(r.item_id), r, entry.conflict_id ? { conflictId: entry.conflict_id } : {});
          items.set(r.item_id, applied.state);
          digests.push(computeStateDigest(items.values()));
        });
        cursor = verified.head;
        serverHead = page.head.log_head;
        if (!page.has_more) break;
      }
      const view: PullView = { state, logSeq: cursor.log_seq, heads, digests, serverHead };
      this.check(view);
      return view;
    }

    /** Spec §6 checks against the highest witnessed checkpoint, including the witnessed position. */
    private check(view: PullView): void {
      if (view.serverHead !== view.heads[view.logSeq]) throw Object.assign(new Error('server head differs from the computed head'), { code: 'rollback' });
      const w = this.witness;
      if (!w) return;
      checkRollback(w.checkpoint, this.incoming(view));
      const at = w.checkpoint.log_seq;
      if (view.digests[at] !== w.checkpoint.state_digest || view.heads[at] !== w.logHead) {
        throw Object.assign(new Error('history at the witnessed position differs'), { code: 'rollback' });
      }
    }

    private incoming(view: PullView) {
      return { vault_id: vaultId, membership_seq: view.state.seq, membership_head: view.state.head, log_seq: view.logSeq, state_digest: view.digests[view.logSeq]!, key_epoch: view.state.key_epoch };
    }

    /** Sign and post a checkpoint for an accepted pull; remember it as witnessed. */
    async checkpoint(view: PullView, expect = 201): Promise<Checkpoint> {
      const cp = signCheckpoint({ ...this.incoming(view), ts: Date.now(), author: this.dev.keys.record.device_id }, this.dev.keys.signSecret);
      expectStatus(`${this.dev.label} posts checkpoint at log_seq ${view.logSeq}`, await api(this.dev, 'POST', `${v}/checkpoints`, cp), expect);
      if (expect === 201) this.witness = { checkpoint: cp, logHead: view.heads[view.logSeq]! };
      return cp;
    }

    /** Pull and expect acceptance, or a refusal with `code`. */
    async expectPull(step: string, outcome: { accept: true; logSeq: number } | { accept: false; code: string }): Promise<PullView | null> {
      try {
        const view = await this.pull();
        if (!outcome.accept) fail(`${step}: expected ${outcome.code}, the client accepted log_seq ${view.logSeq}`);
        if (view.logSeq !== outcome.logSeq) fail(`${step}: expected log_seq ${outcome.logSeq}, got ${view.logSeq}`);
        say(`ok   ${step}: accepted, log_seq ${view.logSeq}, chain and change log verified`);
        return view;
      } catch (err) {
        const code = isAkvError(err) ? err.code : (err as { code?: string }).code;
        if (outcome.accept || code !== outcome.code) throw err;
        say(`ok   ${step}: refused with ${code}`);
        return null;
      }
    }
  }

  /** Poll the restarted object until it serves `logSeq` (restart takes a few seconds). */
  async function waitForLogSeq(dev: Device, logSeq: number, step: string): Promise<void> {
    const t0 = Date.now();
    for (;;) {
      const res = await api(dev, 'GET', `${v}/changes?cursor=0&limit=1`);
      const seq = (res.json?.['head'] as { log_seq?: number } | undefined)?.log_seq;
      if (res.status === 200 && seq === logSeq) {
        say(`ok   ${step}: serving log_seq ${logSeq} after ${((Date.now() - t0) / 1000).toFixed(1)} s`);
        return;
      }
      if (Date.now() - t0 > 60_000) fail(`${step}: still not at log_seq ${logSeq} after 60 s (last ${res.status} ${seq ?? codeOf(res) ?? ''})`);
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  async function restore(target: string, step: string): Promise<{ undo: string; signed: string; before: string }> {
    const current = await currentBookmark(vaultId);
    const signed = signOperatorRequest(operatorSecret, base, { action: 'restore', vault_id: vaultId, bookmark: target, expected_current: current });
    const res = await operator(signed);
    expectStatus(step, res, 200);
    const undo = res.json?.['undo_bookmark'];
    if (res.json?.['restored_to'] !== target || typeof undo !== 'string') fail(`${step}: unexpected response shape`);
    say(`     restored_to ${short(target)} (current was ${short(current)}), undo_bookmark ${short(undo)}`);
    return { undo, signed, before: current };
  }

  /** After a restart: the current bookmark must have moved past the pre-restore one, so a replay is refused. */
  async function bookmarkAfter(before: string, step: string): Promise<string> {
    const after = await currentBookmark(vaultId);
    say(`${after > before ? 'ok  ' : 'FAIL'} ${step}: current bookmark ${short(after)} ${after > before ? 'sorts after' : 'does NOT sort after'} the pre-restore ${short(before)}`);
    if (!(after > before)) fail(`${step}: the current bookmark did not move forward`);
    return after;
  }

  // ---- rehearsal --------------------------------------------------------------------

  expectStatus('healthz', await http('/healthz', { method: 'GET' }), 200);
  const ownerDev = device('owner');
  const laptopDev = device('laptop');
  const owner = new Client(ownerDev);
  const laptop = new Client(laptopDev);

  say('== 1. synthetic vault: genesis, second device, two writes, both devices witness log_seq 2');
  const preGenesis = await currentBookmark(vaultId);
  say(`ok   bookmark of the object before genesis ${short(preGenesis)}`);
  const recovery = signKeyPairFromSeed(randomBytes(32));
  const ownerWrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: ownerDev.keys.record });
  const genesis = buildGenesisEvent(
    {
      vault_id: vaultId,
      ts: Date.now(),
      author: ownerDev.keys.record.device_id,
      body: { vault_kind: 'personal', owner_account: account, recovery_sign_pub: b64encode(recovery.publicKey), devices: [ownerDev.keys.record as unknown as JsonObject], wraps_digest: wrapsDigest([ownerWrap]) },
    },
    ownerDev.keys.signSecret,
  );
  expectStatus('genesis', await api(ownerDev, 'PUT', v, { event: genesis, wraps: [ownerWrap] }), 201);
  const laptopWrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: laptopDev.keys.record });
  const add = nextMembershipEvent(
    verifyMembershipChain([genesis]),
    { type: 'device_add', ts: Date.now(), author: ownerDev.keys.record.device_id, body: { device: laptopDev.keys.record as unknown as JsonObject, sas: b64encode(randomBytes(32)), wraps_digest: wrapsDigest([laptopWrap]) } },
    ownerDev.keys.signSecret,
  );
  expectStatus('device_add (laptop)', await api(ownerDev, 'POST', `${v}/membership`, { event: add, wraps: [laptopWrap] }), 201);
  const itemA = randomId();
  const itemB = randomId();
  await write(ownerDev, itemA, 0, 'synthetic-a1', 'owner writes item A (log_seq 1)');
  await write(ownerDev, itemB, 0, 'synthetic-b1', 'owner writes item B (log_seq 2)');
  await owner.checkpoint((await owner.expectPull('owner pull', { accept: true, logSeq: 2 }))!);
  await laptop.checkpoint((await laptop.expectPull('laptop pull', { accept: true, logSeq: 2 }))!);

  say('== 2. backup: record the current bookmark (exact)');
  const backup = await currentBookmark(vaultId);
  const again = await currentBookmark(vaultId);
  say(`ok   backup bookmark ${short(backup)}; a second read with no writes in between is ${again === backup ? 'identical' : `DIFFERENT (${short(again)})`}`);
  if (again !== backup) fail('the current bookmark moved without a write: compare-and-swap restores cannot work');
  const timeLookup = await operator(signOperatorRequest(operatorSecret, base, { action: 'bookmark', vault_id: vaultId, at_ms: Date.now() - 5_000 }));
  say(`info time lookup 5 s back on this young vault: ${timeLookup.status} ${codeOf(timeLookup) ?? 'bookmark returned'}`);

  say('== 3. laptop writes past the backup and witnesses log_seq 4; the owner does not pull');
  await write(laptopDev, itemA, 1, 'synthetic-a2', 'laptop writes item A rev 2 (log_seq 3)');
  const itemC = randomId();
  await write(laptopDev, itemC, 0, 'synthetic-c1', 'laptop writes item C (log_seq 4)');
  const laptopAt4 = await laptop.checkpoint((await laptop.expectPull('laptop pull', { accept: true, logSeq: 4 }))!);

  say('== 4. restore to the backup through the operator route');
  const first = await restore(backup, 'operator restore to the backup');
  expectStatus('replay of the same signed restore request is refused', await operator(first.signed), 409, 'conflict');
  await waitForLogSeq(ownerDev, 2, 'restored object');
  await bookmarkAfter(first.before, 'after the restore');
  expectStatus('replay of the first restore request after the restart is refused', await operator(first.signed), 409, 'conflict');

  say('== 5. reconciliation after the restore');
  await laptop.expectPull('laptop (witnessed log_seq 4) pulls the restored vault', { accept: false, code: 'rollback' });
  const ownerView = await owner.expectPull('owner (witnessed only log_seq 2) pulls the restored vault', { accept: true, logSeq: 2 });
  say('     the restore is invisible to a device that never saw newer state (documented limitation)');
  expectStatus('laptop re-posts its log_seq 4 checkpoint', await api(laptopDev, 'POST', `${v}/checkpoints`, laptopAt4), 400, 'bad_request');
  const relay = await api(ownerDev, 'GET', `${v}/checkpoints`);
  const relayed = ((relay.json?.['checkpoints'] ?? []) as { log_seq: number }[]).map((c) => c.log_seq);
  say(`ok   checkpoint relay after the restore holds log_seq [${relayed.join(', ')}] (laptop's log_seq 4 checkpoint is gone)`);

  say('== 6. the restored history grows past the laptop\'s witnessed position with different contents');
  await owner.checkpoint(ownerView!);
  const itemD = randomId();
  await write(ownerDev, itemD, 0, 'synthetic-d1', 'owner writes item D (log_seq 3)');
  await write(ownerDev, itemB, 1, 'synthetic-b2', 'owner writes item B rev 2 (log_seq 4)');
  await write(ownerDev, itemD, 1, 'synthetic-d2', 'owner writes item D rev 2 (log_seq 5)');
  await owner.checkpoint((await owner.expectPull('owner pull', { accept: true, logSeq: 5 }))!);
  await laptop.expectPull('laptop (witnessed log_seq 4) pulls the forked log_seq 5', { accept: false, code: 'rollback' });
  try {
    const forked = await new Client(laptopDev).pull();
    checkRollback(laptop.witness!.checkpoint, { vault_id: vaultId, membership_seq: forked.state.seq, membership_head: forked.state.head, log_seq: forked.logSeq, state_digest: forked.digests[forked.logSeq]!, key_epoch: forked.state.key_epoch });
    say('info checkRollback alone (sequence comparison only) passes on the fork; the witnessed-position digest and head check is what refuses it');
  } catch (err) {
    say(`info checkRollback alone also refuses the fork (${isAkvError(err) ? err.code : 'error'})`);
  }

  say('== 7. undo: restore to the undo bookmark');
  const second = await restore(first.undo, 'operator restore to the undo bookmark');
  say(`     the undo bookmark ${first.undo < second.before ? 'sorts before' : 'does not sort before'} the current bookmark it replaced`);
  await waitForLogSeq(ownerDev, 4, 'undone object');
  await bookmarkAfter(second.before, 'after the undo');
  expectReplayRefused('replay of the first restore request after the undo', await operator(first.signed));
  expectStatus('replay of the undo request is refused', await operator(second.signed), 409, 'conflict');
  const laptopView = await laptop.expectPull('laptop pulls after the undo', { accept: true, logSeq: 4 });
  if (laptopView!.digests[4] !== laptopAt4.state_digest) fail('undo did not return the laptop\'s witnessed state');
  say('ok   laptop state digest at log_seq 4 equals its pre-restore checkpoint');
  await owner.expectPull('owner (witnessed the post-restore log_seq 5) pulls after the undo', { accept: false, code: 'rollback' });
  say('     the owner\'s post-restore writes are gone: refused as a rollback, not accepted silently');
  await write(laptopDev, randomId(), 0, 'synthetic-e1', 'a new write after the undo (log_seq 5)');

  say('== 8. a restore to before genesis, and its undo');
  async function vaultExists(): Promise<boolean | null> {
    const res = await operator(signOperatorRequest(operatorSecret, base, { action: 'bookmark', vault_id: vaultId, at_ms: null }));
    return res.status === 200 ? res.json?.['vault_exists'] === true : null;
  }
  {
    const current = await currentBookmark(vaultId);
    const signed = signOperatorRequest(operatorSecret, base, { action: 'restore', vault_id: vaultId, bookmark: preGenesis, expected_current: current });
    const res = await operator(signed);
    if (res.status === 400 && codeOf(res) === 'bad_request') {
      say('info restore to the pre-genesis bookmark: 400 bad_request (the platform refuses it)');
    } else {
      if (res.status !== 200) fail(`restore to the pre-genesis bookmark: expected 200 or a platform 400, got ${res.status} ${codeOf(res) ?? ''}`);
      const undo = res.json?.['undo_bookmark'] as string;
      say(`ok   restore to the pre-genesis bookmark (200), undo_bookmark ${short(undo)}`);
      const t0 = Date.now();
      let exists = await vaultExists();
      while (exists !== false && Date.now() - t0 < 30_000) exists = await vaultExists();
      if (exists !== false) fail(`after the pre-genesis restore the object reports vault_exists ${String(exists)}`);
      say('ok   after it, the object reports vault_exists false');
      expectStatus('a client read of the restored pre-genesis object', await api(ownerDev, 'GET', `${v}/membership`), 404, 'not_found');
      await restore(undo, 'undo of the pre-genesis restore');
      await waitForLogSeq(laptopDev, 5, 'vault after undoing the pre-genesis restore');
      if ((await vaultExists()) !== true) fail('the vault does not exist after undoing the pre-genesis restore');
      say('ok   vault_exists true after the undo');
      await laptop.expectPull('laptop pulls after undoing the pre-genesis restore', { accept: true, logSeq: 5 });
    }
  }

  say('rehearsal passed');
}

try {
  await main();
} catch (err) {
  if (!reportSmokeFailure(err)) throw err;
}

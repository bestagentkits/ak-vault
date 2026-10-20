/**
 * One SQLite-backed Durable Object per vault: the serialization point for every
 * mutation. For an existing vault `handle` runs read-only check of the device's
 * `authorized` rate budget -> Idempotency-Key format (mutations) -> authorization
 * (membership, proof, scope, role) -> charge the `authorized` budget ->
 * idempotency replay -> one `transactionSync` per mutation. A refusal by the
 * Idempotency-Key check or authorization is charged to the device's separate
 * `refused` budget instead; a 429 from the pre-check charges nothing. A missing
 * vault answers 404 and a fresh-vault genesis runs its storage-free checks
 * first; neither charges a budget. Errors leave as stable codes with fixed messages.
 *
 * No storage is written for a vault that does not exist: every op other than
 * genesis answers 404 before the rate counter or proof `jti` tables are touched,
 * and genesis creates the schema only after a storage-free preflight (event,
 * author/owner, scope, proof signature, Idempotency-Key) passes. Only a valid genesis creates state.
 */
import { DurableObject } from 'cloudflare:workers';
import { randomId, type MembershipState, type Role, type SealKeyDoc } from '@ak-vault/protocol';
import type { Env } from '../env.js';
import { ApiError, errorResult, okResult, toApiError, type ApiResult } from '../http/errors.js';
import { appendAudit, readAudit } from './audit-store.js';
import { backfillLogHeads } from './change-log-heads.js';
import { getChanges } from './changes-feed.js';
import { listCheckpoints, postCheckpoint } from './checkpoint-store.js';
import { lookupIdempotent, storeIdempotent, validateIdempotencyKey } from './idempotency.js';
import { getItem, putRecord } from './item-store.js';
import { handleGenesis, handleMembershipGet, handleMembershipPost, handleWrapsGet } from './membership-handlers.js';
import { MembershipStore } from './membership-store.js';
import { bookmarkForTime, currentBookmark, scheduleRestore } from './point-in-time-restore.js';
import { getRecovery, putRecovery } from './recovery-store.js';
import { lookupNameTags } from './lookup-store.js';
import { currentSealKey, getSealKey, putSealKey } from './seal-key-store.js';
import { ackSealedOp, enqueueSealedOp, listSealedOps, type EnqueueSealedResult } from './sealed-store.js';
import { enforceRateLimit, requireRateBudget } from './request-guard.js';
import { authorize, preflightGenesis, type Authorized } from './vault-authorization.js';
import { isMutation, type VaultRequest } from './vault-request.js';
import { VAULT_SCHEMA } from './vault-schema.js';

export class VaultDurableObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private readonly membership: MembershipStore;
  /** Whether the vault tables exist (created by the first genesis attempt). */
  private schemaReady: boolean;
  /** Random per start; the operator route reads it to confirm a restart. */
  private readonly instanceId = randomId();
  /**
   * Set once an operator restore is scheduled. In memory only, so the restart that
   * applies the restore clears it; until then every request is refused, so nothing
   * is acknowledged that the restore would discard.
   */
  private restorePending = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.membership = new MembershipStore(this.sql);
    // Reading sqlite_master writes nothing; re-running the idempotent schema on an
    // existing vault applies any newly added tables or indexes.
    this.schemaReady = this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'").toArray().length > 0;
    if (this.schemaReady) {
      this.sql.exec(VAULT_SCHEMA);
      // Vaults that stored records before change-log heads existed get them once, in log order.
      ctx.storage.transactionSync(() => backfillLogHeads(this.sql));
    }
  }

  /** True once a genesis has been stored; reads only, never creates storage. */
  private vaultExists(): boolean {
    return this.schemaReady && this.membership.state() !== null;
  }

  private ensureSchema(): void {
    if (this.schemaReady) return;
    this.sql.exec(VAULT_SCHEMA);
    this.schemaReady = true;
  }

  async handle(req: VaultRequest): Promise<ApiResult> {
    try {
      this.refuseWhileRestorePending();
      if (req.op === 'genesis') {
        if (!this.schemaReady) {
          // Everything checkable without storage runs before the schema is created.
          preflightGenesis(req);
          validateIdempotencyKey(req.idempotencyKey);
        }
        this.ensureSchema();
      } else if (!this.vaultExists()) throw new ApiError('not_found');
      const auth = this.authorizeAndCharge(req);
      if (!isMutation(req.op)) return this.read(req, auth);
      const replayed = lookupIdempotent(this.sql, req);
      if (replayed) return replayed;
      try {
        return this.ctx.storage.transactionSync(() => {
          const result = this.mutate(req, auth);
          storeIdempotent(this.sql, req, result);
          return result;
        });
      } catch (err) {
        this.membership.invalidate(); // the cached state may describe a rolled-back append
        throw err;
      }
    } catch (err) {
      return errorResult(toApiError(err));
    }
  }

  /**
   * Authorize, then charge the device's `authorized` budget. A refusal charges the
   * `refused` budget instead (answering `rate_limited` once that is spent), so a
   * caller that cannot prove the device key cannot exhaust the device's budget.
   * The refused budget is shared by everyone presenting the device's token: during a
   * flood the device's own refusals also answer `rate_limited`.
   */
  private authorizeAndCharge(req: VaultRequest): Authorized {
    requireRateBudget(this.sql, 'authorized', req.claims.did, req.nowMs);
    let auth: Authorized;
    try {
      if (isMutation(req.op)) validateIdempotencyKey(req.idempotencyKey);
      auth = authorize(req, this.sql, this.membership);
    } catch (err) {
      enforceRateLimit(this.sql, 'refused', req.claims.did, req.nowMs);
      throw err;
    }
    enforceRateLimit(this.sql, 'authorized', req.claims.did, req.nowMs);
    return auth;
  }

  private refuseWhileRestorePending(): void {
    if (this.restorePending) throw new ApiError('internal', { status: 503, message: 'vault restore in progress', headers: { 'Retry-After': '5' } });
  }

  /**
   * Operator point-in-time recovery (RPC from the operator route only; the sync
   * API never reaches it). These also run for an object without a vault, so a
   * restore to before genesis can be undone. Results are plain objects so errors
   * cross RPC as data.
   */
  async operatorBookmark(atMs: number | null, nowMs: number): Promise<ApiResult> {
    try {
      this.refuseWhileRestorePending();
      const storage = this.ctx.storage;
      const bookmark = atMs === null ? await currentBookmark(storage) : await bookmarkForTime(storage, atMs, nowMs);
      return okResult({ bookmark, vault_exists: this.vaultExists() });
    } catch (err) {
      return errorResult(toApiError(err));
    }
  }

  /**
   * Schedule a restore (compare-and-swap on the current bookmark). Returns the undo
   * bookmark; from here until the restart every request is refused.
   */
  async operatorScheduleRestore(target: string, expectedCurrent: string): Promise<ApiResult> {
    try {
      this.refuseWhileRestorePending();
      const undo = await scheduleRestore(this.ctx.storage, target, expectedCurrent, () => {
        this.restorePending = true;
      });
      return okResult({ restored_to: target, undo_bookmark: undo });
    } catch (err) {
      return errorResult(toApiError(err));
    }
  }

  /** Restart the object so a scheduled restore takes effect. The calling RPC receives an error by design. */
  operatorRestart(): void {
    this.ctx.abort('operator point-in-time restore');
  }

  /** This start's instance ID and whether a restore is pending (confirms a restart). */
  operatorInstance(): { instance: string; restorePending: boolean } {
    return { instance: this.instanceId, restorePending: this.restorePending };
  }

  /*
   * Remote-access RPC (ADR 0002), called only by Worker code after it has
   * authenticated its caller: the relay (`hello`, `reauth`, before each call) and
   * the MCP handler (membership, sealing). None of them creates storage for a
   * vault that does not exist, and each answers "no" while a restore is pending.
   */

  /** Current state when the vault exists and no restore is pending, else null. */
  private remoteState(): MembershipState | null {
    try {
      if (this.restorePending || !this.vaultExists()) return null;
      return this.membership.state();
    } catch {
      return null; // a vault this revision refuses (see MembershipStore.state) is never a remote target
    }
  }

  /**
   * The role of `did` when it is a current `human` device of account `sub` (also a
   * current member) whose `sign_pub` is `signPub`, else null (spec §9.7 `hello`
   * and per-call checks).
   */
  async memberDeviceRole(did: string, sub: string, signPub: string): Promise<Role | null> {
    const state = this.remoteState();
    if (!state) return null;
    const device = state.devices.find((d) => d.device_id === did);
    if (!device || device.account !== sub || device.kind !== 'human' || device.sign_pub !== signPub) return null;
    if (!state.members.some((m) => m.account === sub)) return null;
    return device.role;
  }

  /** The role of account `sub` when it is a current member, else null (MCP membership check, spec §9.8). */
  async accountRole(sub: string): Promise<Role | null> {
    return this.remoteState()?.members.find((m) => m.account === sub)?.role ?? null;
  }

  /**
   * The seal-key document the MCP handler may seal to: the current key epoch's,
   * and none while `rekey_required` is set (a removed device may still derive
   * that epoch's seal key, spec §3.6).
   */
  async getSealKey(): Promise<SealKeyDoc | null> {
    const state = this.remoteState();
    if (!state || state.rekey_required) return null;
    return currentSealKey(this.sql, state);
  }

  /** Queue a sealed operation built by the MCP handler (the only way one enters the queue). */
  async enqueueSealed(wire: unknown, nowMs: number = Date.now()): Promise<EnqueueSealedResult> {
    const state = this.remoteState();
    if (!state) return 'refused';
    return this.ctx.storage.transactionSync(() => enqueueSealedOp(this.sql, state, wire, nowMs));
  }

  private read(req: VaultRequest, auth: Authorized): ApiResult {
    switch (req.op) {
      case 'membership.get':
        return handleMembershipGet(this.membership, req);
      case 'wraps.get':
        return handleWrapsGet(this.sql, auth.state, req);
      case 'item.get':
        return getItem(this.sql, req.itemId!);
      case 'changes.get':
        return getChanges(this.sql, auth.state, req);
      case 'checkpoints.get':
        return listCheckpoints(this.sql, auth.state);
      case 'audit.get':
        return readAudit(this.sql, auth.state, req);
      case 'recovery.get':
        return getRecovery(this.sql);
      case 'lookup.get':
        return lookupNameTags(this.sql, auth.state, req);
      case 'sealkey.get':
        return getSealKey(this.sql, auth.state);
      case 'sealed.get':
        return listSealedOps(this.sql, req);
      default:
        throw new ApiError('not_found');
    }
  }

  private mutate(req: VaultRequest, auth: Authorized): ApiResult {
    const body = auth.body!;
    switch (req.op) {
      case 'genesis':
        return handleGenesis(this.sql, this.membership, body, auth.state);
      case 'membership.post':
        return handleMembershipPost(this.sql, this.membership, req.vaultId, body, auth.next ?? this.membership.verifyAppend(body['event']));
      case 'item.put':
        return putRecord(this.sql, auth.state, req.claims.did, req.itemId!, body, { remoteAccess: req.remoteAccess });
      case 'sealkey.put':
        return putSealKey(this.sql, auth.state, req.claims.did, this.membership.chain(), body);
      case 'sealed.ack':
        return ackSealedOp(this.sql, req, body);
      case 'checkpoints.post':
        return postCheckpoint(this.sql, this.membership, auth.state, req.claims.did, body);
      case 'audit.post':
        return appendAudit(this.sql, auth.state, req.claims.did, body);
      case 'recovery.put':
        return putRecovery(this.sql, auth.state, req.vaultId, body);
      default:
        throw new ApiError('not_found');
    }
  }
}

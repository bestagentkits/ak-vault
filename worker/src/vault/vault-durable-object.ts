/**
 * One SQLite-backed Durable Object per vault: the serialization point for every
 * mutation. `handle` runs vault-exists check -> authorization (membership,
 * proof, scope, role) -> rate limit -> idempotency -> one `transactionSync` per
 * mutation. A request refused at authorization is counted against the device's
 * separate `refused` budget, never its `authorized` one. Errors leave as stable
 * codes with fixed messages.
 *
 * No storage is written for a vault that does not exist: every op other than
 * genesis answers 404 before the rate counter or proof `jti` tables are touched,
 * and genesis creates the schema only after a storage-free preflight (event,
 * author/owner, scope, proof signature) passes. Only a valid genesis creates state.
 */
import { DurableObject } from 'cloudflare:workers';
import { randomId } from '@ak-vault/protocol';
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
import { enforceRateLimit } from './request-guard.js';
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
        if (!this.schemaReady) preflightGenesis(req);
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
   */
  private authorizeAndCharge(req: VaultRequest): Authorized {
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
        return putRecord(this.sql, auth.state, req.claims.did, req.itemId!, body);
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

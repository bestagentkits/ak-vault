/**
 * One SQLite-backed Durable Object per vault: the serialization point for every
 * mutation. `handle` runs vault-exists check -> rate limit -> authorization
 * (membership, proof, scope, role) -> idempotency -> one `transactionSync` per
 * mutation. Errors leave as stable codes with fixed messages.
 *
 * No storage is written for a vault that does not exist: every op other than
 * genesis answers 404 before the rate counter or proof `jti` tables are touched,
 * and genesis creates the schema only after a storage-free preflight (event,
 * author/owner, scope, proof signature) passes. Only a valid genesis creates state.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env.js';
import { ApiError, errorResult, toApiError, type ApiResult } from '../http/errors.js';
import { appendAudit, readAudit } from './audit-store.js';
import { getChanges } from './changes-feed.js';
import { listCheckpoints, postCheckpoint } from './checkpoint-store.js';
import { lookupIdempotent, storeIdempotent, validateIdempotencyKey } from './idempotency.js';
import { getItem, putRecord } from './item-store.js';
import { handleGenesis, handleMembershipGet, handleMembershipPost, handleWrapsGet } from './membership-handlers.js';
import { MembershipStore } from './membership-store.js';
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

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.membership = new MembershipStore(this.sql);
    // Reading sqlite_master writes nothing; re-running the idempotent schema on an
    // existing vault applies any newly added tables or indexes.
    this.schemaReady = this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'").toArray().length > 0;
    if (this.schemaReady) this.sql.exec(VAULT_SCHEMA);
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
      if (req.op === 'genesis') {
        if (!this.schemaReady) preflightGenesis(req);
        this.ensureSchema();
      } else if (!this.vaultExists()) throw new ApiError('not_found');
      enforceRateLimit(this.sql, req.claims.did, req.nowMs);
      if (isMutation(req.op)) validateIdempotencyKey(req.idempotencyKey);
      const auth = authorize(req, this.sql, this.membership);
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
        return putRecovery(this.sql, req.vaultId, body);
      default:
        throw new ApiError('not_found');
    }
  }
}

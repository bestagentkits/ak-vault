/**
 * One SQLite-backed Durable Object per vault: the serialization point for every
 * mutation. `handle` runs rate limit -> authorization (membership, proof, scope,
 * role) -> idempotency -> one `transactionSync` per mutation. Errors leave as
 * stable codes with fixed messages.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env.js';
import { ApiError, errorResult, toApiError, type ApiResult } from '../http/errors.js';
import { appendAudit, readAudit } from './audit-store.js';
import { getChanges } from './changes-feed.js';
import { listCheckpoints, postCheckpoint } from './checkpoint-store.js';
import { lookupIdempotent, storeIdempotent, validateIdempotencyKey } from './idempotency.js';
import { getItem, putRecord } from './item-store.js';
import { handleGenesis, handleMembershipGet, handleMembershipPost, handleWrapsGet, handleWrapsPost } from './membership-handlers.js';
import { MembershipStore } from './membership-store.js';
import { getRecovery, putRecovery } from './recovery-store.js';
import { enforceRateLimit } from './request-guard.js';
import { authorize, type Authorized } from './vault-authorization.js';
import { isMutation, type VaultRequest } from './vault-request.js';
import { VAULT_SCHEMA } from './vault-schema.js';

export class VaultDurableObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private readonly membership: MembershipStore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(VAULT_SCHEMA);
    this.membership = new MembershipStore(this.sql);
  }

  async handle(req: VaultRequest): Promise<ApiResult> {
    try {
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
        return handleMembershipPost(this.sql, this.membership, body, auth.next ?? this.membership.verifyAppend(body['event']));
      case 'wraps.post':
        return handleWrapsPost(this.sql, auth.state, body);
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

/**
 * Encrypted audit stream (spec §7), stored apart from the operational log. The
 * server cannot decrypt entries (the AAD binds seq, prev and key_epoch), so it
 * enforces the structure it can see: envelope shape, kid = the current key epoch, append-only continuity (`start_seq` and
 * `prev` must equal the stored head, else 409 so the client re-seals), unique
 * nonces, and audit checkpoints that are signed by the posting device, match the
 * stored chain hash, and never move backwards (`rollback`).
 *
 * POST body: {"start_seq":n, "prev":"<hash of entry n-1 or ''>", "entries":[envelope], "checkpoint"?: audit checkpoint}
 */
import { assertUniqueNonces, auditEntryHash, cjson, epochTag, parseEnvelope, parseJson, parseAuditCheckpoint, verifyAuditCheckpoint, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { queryInt, requireArray, requireInt, requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

function auditHead(sql: SqlStorage): { seq: number; head: string } | null {
  const row = sql.exec<{ seq: number; hash: string }>('SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1').toArray()[0];
  return row ? { seq: row.seq, head: row.hash } : null;
}

function storeAuditCheckpoint(sql: SqlStorage, state: MembershipState, did: string, raw: unknown): void {
  const cp = verifyAuditCheckpoint(raw, state);
  if (cp.author !== did) throw new ApiError('forbidden', { message: 'audit checkpoint author is not the authenticated device' });
  const hash = sql.exec<{ hash: string }>('SELECT hash FROM audit_entries WHERE seq = ?', cp.seq).toArray()[0]?.hash;
  if (hash === undefined) throw new ApiError('bad_request', { message: 'audit checkpoint is ahead of the stored chain' });
  if (hash !== cp.head) throw new ApiError('rollback', { message: 'audit checkpoint forks from the stored chain' });
  const previous = sql.exec<{ checkpoint_json: string }>('SELECT checkpoint_json FROM audit_checkpoints WHERE author = ?', did).toArray()[0];
  if (previous) {
    const old = parseAuditCheckpoint(parseJson(previous.checkpoint_json));
    if (cp.seq < old.seq || (cp.seq === old.seq && cp.head !== old.head)) throw new ApiError('rollback');
  }
  sql.exec(
    'INSERT INTO audit_checkpoints (author, seq, checkpoint_json) VALUES (?, ?, ?) ON CONFLICT (author) DO UPDATE SET seq = excluded.seq, checkpoint_json = excluded.checkpoint_json',
    did,
    cp.seq,
    cjson(cp as unknown as JsonObject),
  );
}

export function appendAudit(sql: SqlStorage, state: MembershipState, did: string, body: JsonObject): ApiResult {
  requireKeys(body, ['start_seq', 'prev', 'entries'], ['checkpoint']);
  const startSeq = requireInt(body['start_seq']);
  const prev = body['prev'];
  const entries = requireArray(body['entries'], LIMITS.audit_batch_max).map((e, i) => parseEnvelope(e, `audit entry ${i}`));
  if (entries.length === 0 && body['checkpoint'] === undefined) throw new ApiError('bad_request');
  assertUniqueNonces(entries);
  // Entries are sealed under the audit key of the current epoch; a lagging device re-pulls and re-seals.
  const kid = epochTag(state.key_epoch);
  for (const entry of entries) if (entry.kid !== kid) throw new ApiError('bad_request', { message: 'audit entry is not sealed for the current key epoch' });
  for (const entry of entries) if (cjson(entry as unknown as JsonObject).length > LIMITS.envelope_max_bytes) throw new ApiError('quota_exceeded');

  const head = auditHead(sql);
  if (startSeq !== (head ? head.seq + 1 : 0) || prev !== (head ? head.head : '')) throw new ApiError('conflict', { message: 'audit chain head moved' });
  if (startSeq + entries.length > LIMITS.audit_entries_per_vault) throw new ApiError('quota_exceeded', { status: 403 });
  entries.forEach((entry, i) => {
    if (sql.exec('SELECT 1 FROM audit_entries WHERE nonce = ?', entry.n).toArray().length > 0) throw new ApiError('bad_request', { message: 'reused audit nonce' });
    sql.exec('INSERT INTO audit_entries (seq, hash, nonce, entry_json) VALUES (?, ?, ?, ?)', startSeq + i, auditEntryHash(entry), entry.n, cjson(entry as unknown as JsonObject));
  });
  if (body['checkpoint'] !== undefined) storeAuditCheckpoint(sql, state, did, body['checkpoint']);
  return okResult({ head: auditHead(sql) }, 201);
}

export function readAudit(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  const cursor = queryInt(req.query, 'cursor', 0);
  const limit = Math.max(1, queryInt(req.query, 'limit', LIMITS.audit_page_max, LIMITS.audit_page_max));
  const rows = sql.exec<{ seq: number; entry_json: string }>('SELECT seq, entry_json FROM audit_entries WHERE seq >= ? ORDER BY seq LIMIT ?', cursor, limit + 1).toArray();
  const page = rows.slice(0, limit);
  const current = new Set(state.devices.map((d) => d.device_id));
  const checkpoints = sql
    .exec<{ author: string; checkpoint_json: string }>('SELECT author, checkpoint_json FROM audit_checkpoints ORDER BY seq DESC, author')
    .toArray()
    .filter((r) => current.has(r.author))
    .map((r) => JSON.parse(r.checkpoint_json) as unknown);
  return okResult({
    entries: page.map((r) => ({ seq: r.seq, entry: JSON.parse(r.entry_json) as unknown })),
    next_cursor: page.length > 0 ? page[page.length - 1]!.seq + 1 : cursor,
    has_more: rows.length > limit,
    head: auditHead(sql),
    checkpoints,
  });
}

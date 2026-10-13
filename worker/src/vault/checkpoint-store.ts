/**
 * Client-signed checkpoints (spec §6). The server relays the latest checkpoint
 * per device so other devices have a second channel against rollback. A posted
 * checkpoint must be signed by the authenticated current device, must describe a
 * state the server actually has (membership head at that seq, log_seq not ahead),
 * and must not be behind or forked from that device's previous checkpoint
 * (`rollback`).
 */
import { checkRollback, cjson, parseCheckpoint, parseJson, verifyCheckpoint, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { currentLogSeq } from './changes-feed.js';
import type { MembershipStore } from './membership-store.js';

export function postCheckpoint(sql: SqlStorage, store: MembershipStore, state: MembershipState, did: string, body: unknown): ApiResult {
  const cp = verifyCheckpoint(body, state);
  if (cp.author !== did) throw new ApiError('forbidden', { message: 'checkpoint author is not the authenticated device' });
  if (cp.membership_seq > state.seq || cp.log_seq > currentLogSeq(sql) || cp.key_epoch > state.key_epoch) throw new ApiError('bad_request', { message: 'checkpoint is ahead of the stored state' });
  if (store.eventHash(cp.membership_seq) !== cp.membership_head) throw new ApiError('rollback', { message: 'checkpoint membership head forks from the stored chain' });
  const previous = sql.exec<{ checkpoint_json: string }>('SELECT checkpoint_json FROM checkpoints WHERE author = ?', did).toArray()[0];
  if (previous) checkRollback(parseCheckpoint(parseJson(previous.checkpoint_json)), cp);
  sql.exec(
    `INSERT INTO checkpoints (author, membership_seq, log_seq, checkpoint_json) VALUES (?, ?, ?, ?)
     ON CONFLICT (author) DO UPDATE SET membership_seq = excluded.membership_seq, log_seq = excluded.log_seq, checkpoint_json = excluded.checkpoint_json`,
    did,
    cp.membership_seq,
    cp.log_seq,
    cjson(cp as unknown as JsonObject),
  );
  return okResult({ stored: true }, 201);
}

/** Latest checkpoint of each current device. */
export function listCheckpoints(sql: SqlStorage, state: MembershipState): ApiResult {
  const current = new Set(state.devices.map((d) => d.device_id));
  const checkpoints = sql
    .exec<{ author: string; checkpoint_json: string }>('SELECT author, checkpoint_json FROM checkpoints ORDER BY log_seq DESC, author')
    .toArray()
    .filter((r) => current.has(r.author))
    .map((r) => JSON.parse(r.checkpoint_json) as unknown);
  return okResult({ checkpoints });
}

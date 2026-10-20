/**
 * Name tags and `GET /lookup` (spec §3.7, §9.6). Devices compute the tags; the
 * server only stores the tag a writer sent beside an applied record and matches
 * requested `(key_epoch, tag)` pairs against current heads. It never holds the
 * index key, never computes a tag and never trusts one: a hit is a hint the
 * reader verifies against the decrypted record.
 */
import { NAME_TAG_BYTES, b64decodeLength, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';
import { requireInt, requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

export interface NameTag {
  key_epoch: number;
  tag: string;
}

/** An item PUT body: the bare record, or the `{record, name_tag}` wrapper. */
export interface ItemPutBody {
  record: unknown;
  nameTag: NameTag | null;
}

function parseTag(value: unknown): string {
  try {
    if (typeof value !== 'string') throw new ApiError('bad_request');
    b64decodeLength(value, NAME_TAG_BYTES);
  } catch {
    throw new ApiError('bad_request', { message: 'name tag must be 16 bytes of base64url' });
  }
  return value;
}

/**
 * Split an item PUT body. A body with a `record` key is the wrapper (a bare
 * record never has one); the wrapper is `bad_request` where remote access is off.
 */
export function parseItemPutBody(body: JsonObject, remoteAccess: boolean): ItemPutBody {
  if (!('record' in body)) return { record: body, nameTag: null };
  if (!remoteAccess) throw new ApiError('bad_request', { message: 'name tags are not accepted by this deployment' });
  requireKeys(body, ['record'], ['name_tag']);
  const raw = body['name_tag'];
  if (raw === undefined) return { record: body['record'], nameTag: null };
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new ApiError('bad_request');
  requireKeys(raw, ['key_epoch', 'tag']);
  return { record: body['record'], nameTag: { key_epoch: requireInt(raw['key_epoch'], 1), tag: parseTag(raw['tag']) } };
}

/**
 * Check the tag against the verified record it travels with: same key epoch,
 * and never on a tombstone (`bad_request`).
 */
export function checkNameTag(tag: NameTag | null, record: { key_epoch: number; tombstone: boolean }): void {
  if (!tag) return;
  if (tag.key_epoch !== record.key_epoch) throw new ApiError('bad_request', { message: 'name tag key_epoch does not match the record' });
  if (record.tombstone) throw new ApiError('bad_request', { message: 'a tombstone carries no name tag' });
}

/** After an applied record: store its tag, or clear the item's tag when it carries none. Caller holds the transaction. */
export function setItemNameTag(sql: SqlStorage, itemId: string, revision: number, tag: NameTag | null): void {
  if (!tag) {
    sql.exec('DELETE FROM name_tags WHERE item_id = ?', itemId);
    return;
  }
  sql.exec(
    `INSERT INTO name_tags (item_id, key_epoch, tag, revision) VALUES (?, ?, ?, ?)
     ON CONFLICT (item_id) DO UPDATE SET key_epoch = excluded.key_epoch, tag = excluded.tag, revision = excluded.revision`,
    itemId,
    tag.key_epoch,
    tag.tag,
    revision,
  );
}

/** Parse the `tag` / `key_epoch` query pairs of a lookup (only those two parameters are allowed). */
function lookupPairs(req: VaultRequest, state: MembershipState): NameTag[] {
  const tags: string[] = [];
  const epochs: number[] = [];
  for (const [name, value] of req.queryList) {
    if (name === 'tag') tags.push(parseTag(value));
    else if (name === 'key_epoch') {
      if (!/^\d{1,16}$/.test(value)) throw new ApiError('bad_request');
      const epoch = Number(value);
      if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > state.key_epoch) throw new ApiError('bad_request', { message: 'key_epoch is outside the vault epochs' });
      epochs.push(epoch);
    } else throw new ApiError('bad_request', { message: 'unknown query parameter' });
  }
  if (tags.length === 0 || tags.length !== epochs.length || tags.length > REMOTE_ACCESS_LIMITS.lookup_tags_max) {
    throw new ApiError('bad_request', { message: 'lookup needs 1 to lookup_tags_max tag and key_epoch pairs' });
  }
  return tags.map((tag, i) => ({ tag, key_epoch: epochs[i]! }));
}

/** `GET /lookup`: items whose current head carries a requested pair, in `item_id` byte order. */
export function lookupNameTags(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  const pairs = lookupPairs(req, state);
  const hits = new Map<string, { item_id: string; revision: number; key_epoch: number; tag: string }>();
  for (const { tag, key_epoch } of pairs) {
    const rows = sql.exec<{ item_id: string; revision: number; key_epoch: number; tag: string }>(
      'SELECT item_id, revision, key_epoch, tag FROM name_tags WHERE tag = ? AND key_epoch = ?',
      tag,
      key_epoch,
    );
    for (const row of rows) hits.set(row.item_id, { item_id: row.item_id, revision: row.revision, key_epoch: row.key_epoch, tag: row.tag });
  }
  // IDs are base64url (ASCII), so UTF-16 order is byte order.
  const sorted = [...hits.values()].sort((a, b) => (a.item_id < b.item_id ? -1 : a.item_id > b.item_id ? 1 : 0));
  return okResult({ hits: sorted });
}

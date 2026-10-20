/**
 * Owner-signed seal-key documents (spec §3.6, §9.6). The server cannot check
 * `seal_pub` against a vault key it never holds; it runs `verifySealKeyDoc`
 * steps 1–5 against its stored, anchor-pinned chain, requires the current key
 * epoch and the calling device as author, and keeps one document per epoch
 * (an older `membership_seq` for the same epoch is `409 conflict`).
 */
import { checkSealKeyDocReplace, cjson, parseJson, parseSealKeyDoc, verifySealKeyDoc, type JsonObject, type MembershipState, type SealKeyDoc } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { requireKeys } from './request-body.js';

function storedDoc(sql: SqlStorage, keyEpoch: number): SealKeyDoc | null {
  const row = sql.exec<{ doc: string }>('SELECT doc FROM seal_keys WHERE key_epoch = ?', keyEpoch).toArray()[0];
  return row ? parseSealKeyDoc(parseJson(row.doc)) : null;
}

/** The document for the vault's current key epoch, or null. */
export function currentSealKey(sql: SqlStorage, state: MembershipState): SealKeyDoc | null {
  return storedDoc(sql, state.key_epoch);
}

/** `GET /seal-key`. */
export function getSealKey(sql: SqlStorage, state: MembershipState): ApiResult {
  const doc = currentSealKey(sql, state);
  if (!doc) throw new ApiError('not_found');
  return okResult({ seal_key: doc });
}

/** `PUT /seal-key` by an owner device (authorized by the caller). Caller holds the transaction. */
export function putSealKey(sql: SqlStorage, state: MembershipState, did: string, chain: readonly unknown[], body: JsonObject): ApiResult {
  requireKeys(body, ['seal_key']);
  const doc = verifySealKeyDoc(body['seal_key'], chain, { vaultId: state.vault_id, trustedAnchor: state.trust_anchor });
  if (doc.key_epoch !== state.key_epoch) throw new ApiError('bad_request', { message: 'seal-key document is not for the current key epoch' });
  if (doc.author !== did) throw new ApiError('forbidden', { message: 'seal-key document author is not the authenticated device' });
  checkSealKeyDocReplace(storedDoc(sql, doc.key_epoch), doc);
  sql.exec(
    'INSERT INTO seal_keys (key_epoch, doc, membership_seq) VALUES (?, ?, ?) ON CONFLICT (key_epoch) DO UPDATE SET doc = excluded.doc, membership_seq = excluded.membership_seq',
    doc.key_epoch,
    cjson(doc as unknown as JsonObject),
    doc.membership_seq,
  );
  return okResult({ key_epoch: doc.key_epoch, membership_seq: doc.membership_seq });
}

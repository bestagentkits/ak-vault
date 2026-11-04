/**
 * Change-feed head tag (spec §5, `GET /changes`): a digest of every head field a
 * client keeps from a pull. A client sends the tag of the head it holds as `if_head`;
 * the server answers `304` with no body when the vault's head still has that tag and
 * the cursor is at the head, so a pull with nothing new transfers and reads nothing.
 */
import { sha256b64 } from './base64url.js';
import { cjsonBytes } from './canonical-json.js';

export interface ChangesHead {
  log_seq: number;
  log_head: string;
  membership_seq: number;
  membership_head: string;
  key_epoch: number;
  rekey_required: boolean;
}

/** b64url(sha256(cjson(head))) over exactly the six head fields. */
export function changesHeadTag(head: ChangesHead): string {
  return sha256b64(
    cjsonBytes({
      log_seq: head.log_seq,
      log_head: head.log_head,
      membership_seq: head.membership_seq,
      membership_head: head.membership_head,
      key_epoch: head.key_epoch,
      rekey_required: head.rekey_required,
    }),
  );
}

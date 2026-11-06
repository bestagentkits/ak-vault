/** changes-head-tag.json */
import { changesHeadTag, sha256b64, utf8Encode, type ChangesHead } from '../../src/index.js';

const h = (s: string) => sha256b64(utf8Encode(s));

export function changesHeadTagVectors(): Record<string, unknown> {
  const base: ChangesHead = { log_seq: 7, log_head: h('log'), membership_seq: 3, membership_head: h('membership'), key_epoch: 1, rekey_required: false };
  const heads: ChangesHead[] = [
    base,
    { ...base, log_seq: 0 },
    { ...base, log_seq: 8, log_head: h('log-8') },
    { ...base, membership_seq: 4, membership_head: h('membership-4') },
    { ...base, key_epoch: 2 },
    { ...base, rekey_required: true },
  ];
  return {
    version: 1,
    description: 'Change-feed head tag (spec §5 GET /changes): b64url(sha256(cjson(head))) over log_seq, log_head, membership_seq, membership_head, key_epoch, rekey_required.',
    cases: heads.map((head) => ({ head, tag: changesHeadTag(head) })),
  };
}

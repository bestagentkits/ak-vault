/**
 * SQLite schema of one vault Durable Object. Every column holds either
 * ciphertext/signed protocol objects or the visible metadata listed in
 * docs/security/data-classification.md. Nothing here is plaintext secret data.
 */
import { MCP_MAX_LIFETIME_SECONDS } from '../auth/jwt-verify.js';
import { LIMITS } from '../limits.js';

export const VAULT_SCHEMA = `
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS membership_events (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, event_json TEXT NOT NULL);
  -- The wrap set uploaded with the owner-signed event at membership_seq, verified against its wraps_digest.
  CREATE TABLE IF NOT EXISTS wrap_sets (
    membership_seq INTEGER NOT NULL, rcpt TEXT NOT NULL, key_epoch INTEGER NOT NULL, wrap_json TEXT NOT NULL,
    PRIMARY KEY (membership_seq, rcpt, key_epoch)
  );
  CREATE TABLE IF NOT EXISTS items (
    item_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, tombstone INTEGER NOT NULL,
    tombstone_revision INTEGER NOT NULL, head TEXT NOT NULL, head_log_seq INTEGER NOT NULL
  );
  -- Every accepted record (applied or preserved as a conflict branch). log_seq is the change-log cursor:
  -- assigned as MAX + 1 inside the write transaction, so positions start at 1 and are contiguous.
  CREATE TABLE IF NOT EXISTS records (
    log_seq INTEGER PRIMARY KEY AUTOINCREMENT, item_id TEXT NOT NULL, kind TEXT NOT NULL,
    revision INTEGER, conflict_id TEXT, digest TEXT NOT NULL, record_json TEXT NOT NULL,
    UNIQUE (item_id, digest)
  );
  -- log_heads.head at log_seq n = nextLogHead(head at n - 1, n, conflict_id, digest) of the record at n (spec §5).
  CREATE TABLE IF NOT EXISTS log_heads (log_seq INTEGER PRIMARY KEY, head TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS conflicts (
    conflict_id TEXT PRIMARY KEY, item_id TEXT NOT NULL, log_seq INTEGER NOT NULL, resolved_revision INTEGER
  );
  CREATE INDEX IF NOT EXISTS conflicts_open ON conflicts (item_id) WHERE resolved_revision IS NULL;
  CREATE TABLE IF NOT EXISTS checkpoints (
    author TEXT PRIMARY KEY, membership_seq INTEGER NOT NULL, log_seq INTEGER NOT NULL, checkpoint_json TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_entries (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, entry_json TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS audit_checkpoints (author TEXT PRIMARY KEY, seq INTEGER NOT NULL, checkpoint_json TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS recovery_blob (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL, bundle TEXT NOT NULL);
  -- key_hash = sha256(device_id || "\\n" || Idempotency-Key); the raw key is never stored.
  CREATE TABLE IF NOT EXISTS idempotency (
    key_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, status INTEGER NOT NULL, body_json TEXT NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idempotency_expiry ON idempotency (expires_at);
  CREATE TABLE IF NOT EXISTS proof_jti (did TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (did, jti));
  CREATE INDEX IF NOT EXISTS proof_jti_expiry ON proof_jti (expires_at);
  CREATE TABLE IF NOT EXISTS rate_counters (did TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);
  -- Requests refused before or during authorization, counted apart so they never spend rate_counters.
  CREATE TABLE IF NOT EXISTS refused_rate_counters (did TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);
  -- Recovery-identity requests per account (the vault's owner), whatever device ID the token names.
  CREATE TABLE IF NOT EXISTS recovery_identity_rate_counters (account TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);
  -- Remote access (spec §3.6, §3.7). name_tags: the device-computed tag sent beside each item's current
  -- head (unsigned, untrusted; the server never computes one). seal_keys: one owner-signed seal-key
  -- document per key epoch. sealed_ops: opaque sealed writes queued for the account's own devices; an
  -- acknowledged row keeps only its ID and outcome (ciphertext cleared) until it expires, so a replayed
  -- sealed_id is refused for its whole lifetime. grant_id and token_iat (the MCP grant and the token's iat
  -- that queued the op) let the Worker cancel a pending op whose grant was revoked; rows queued before
  -- they existed are backfilled from their wire when the columns are added.
  CREATE TABLE IF NOT EXISTS name_tags (item_id TEXT PRIMARY KEY, key_epoch INTEGER NOT NULL, tag TEXT NOT NULL, revision INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS name_tags_lookup ON name_tags (tag, key_epoch);
  CREATE TABLE IF NOT EXISTS seal_keys (key_epoch INTEGER PRIMARY KEY, doc TEXT NOT NULL, membership_seq INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS sealed_ops (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, sealed_id TEXT NOT NULL UNIQUE, account TEXT NOT NULL,
    wire TEXT, outcome TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, grant_id TEXT, token_iat INTEGER
  );
  CREATE INDEX IF NOT EXISTS sealed_ops_pending ON sealed_ops (account, seq) WHERE outcome IS NULL;
  CREATE INDEX IF NOT EXISTS sealed_ops_expiry ON sealed_ops (expires_at);
  -- Human write requests (spec §3.10): a person types the value in the dashboard instead of the AI client.
  -- intent is the sealed write intent (the secret name is only inside its ciphertext) and is cleared when the
  -- request closes or expires; the row keeps the sanitized outcome until it is purged.
  CREATE TABLE IF NOT EXISTS write_requests (
    request_id TEXT PRIMARY KEY, account TEXT NOT NULL, client_id TEXT NOT NULL, grant_id TEXT NOT NULL,
    token_iat INTEGER NOT NULL, operation TEXT NOT NULL, state TEXT NOT NULL, intent TEXT, reason TEXT, receipt TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, closed_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS write_requests_account ON write_requests (account, state);
`;

/**
 * Lower bound, in seconds before queue time, for the `iat` of the MCP token that queued a sealed
 * row stored without one: the token lives at most MCP_MAX_LIFETIME_SECONDS, is accepted up to
 * clock_skew_seconds past `exp`, and the request then takes some time to reach the queue (allowed
 * another clock_skew_seconds). Too low only over-cancels under a minimum-iat revocation, the
 * fail-closed direction; too high would let a revoked token's operation be served.
 */
const LEGACY_SEALED_IAT_MARGIN_S = MCP_MAX_LIFETIME_SECONDS + 2 * LIMITS.clock_skew_seconds;

/**
 * Apply the idempotent schema, then add the sealed_ops grant columns to a table created before
 * they existed (CREATE TABLE IF NOT EXISTS leaves such a table unchanged), and backfill every
 * pending row stored without them. The backfill runs on every start, not only when a column is
 * added: a row written by an earlier revision after the columns existed (a rollback, then a roll
 * forward) must not stay uncancellable.
 */
export function applyVaultSchema(sql: SqlStorage): void {
  sql.exec(VAULT_SCHEMA);
  const columns = sql.exec<{ name: string }>("SELECT name FROM pragma_table_info('sealed_ops')").toArray().map((c) => c.name);
  if (!columns.includes('grant_id')) sql.exec('ALTER TABLE sealed_ops ADD COLUMN grant_id TEXT');
  if (!columns.includes('token_iat')) sql.exec('ALTER TABLE sealed_ops ADD COLUMN token_iat INTEGER');
  // The grant is inside the stored wire; the token iat is bounded from below by queue time.
  sql.exec(
    "UPDATE sealed_ops SET grant_id = COALESCE(grant_id, json_extract(wire, '$.origin.grant_id')), token_iat = COALESCE(token_iat, created_at / 1000 - ?) WHERE wire IS NOT NULL AND (grant_id IS NULL OR token_iat IS NULL)",
    LEGACY_SEALED_IAT_MARGIN_S,
  );
}

/**
 * SQLite schema of one vault Durable Object. Every column holds either
 * ciphertext/signed protocol objects or the visible metadata listed in
 * docs/security/data-classification.md. Nothing here is plaintext secret data.
 */
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
`;

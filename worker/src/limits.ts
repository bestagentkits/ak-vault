/**
 * Single owner of every server limit (spec §10). `GET /v1/meta` publishes this
 * object verbatim, so clients and docs read limits from here, never from copies.
 */
export const LIMITS = {
  /** Max bytes of `cjson(record.env)` for one item record. */
  envelope_max_bytes: 64 * 1024,
  /** Max request body bytes for any API request. */
  request_body_max_bytes: 256 * 1024,
  /** Max distinct items (live or tombstoned) per vault. */
  items_per_vault: 2000,
  /**
   * Max stored records (applied revisions plus preserved conflict branches) per
   * vault. The change log is append-only, so this bounds history growth.
   */
  records_per_vault: 200_000,
  /**
   * Max total bytes of stored records per vault (`cjson(record)` sizes). Keeps a
   * single writer far below the 10 GB Durable Object storage ceiling.
   */
  record_bytes_per_vault: 512 * 1024 * 1024,
  /** Max open (unresolved) preserved conflict branches per vault. */
  open_conflicts_per_vault: 256,
  /** `GET /changes` page size. */
  changes_page_default: 100,
  changes_page_max: 500,
  /** `GET /membership` page size. */
  membership_page_max: 1000,
  /**
   * Max membership events per vault (the chain is replayed on every append). The
   * last slot is kept for a rekey that clears `rekey_required`, so a removal can
   * never take the slot its own rekey needs.
   */
  membership_events_per_vault: 10_000,
  /**
   * Max current devices after an owner-authored device_add or member_add. One
   * more is kept for a recovery enrollment, so a rekey of every device always
   * fits `wraps_per_request`.
   */
  devices_per_vault: 255,
  /** Max decoded bytes of the opaque recovery bundle. */
  recovery_blob_max_bytes: 16 * 1024,
  /** Max entries per audit append. */
  audit_batch_max: 100,
  /** Max audit entries per vault. */
  audit_entries_per_vault: 100_000,
  /** `GET /audit` page size. */
  audit_page_max: 500,
  /** Max wraps in one upload. */
  wraps_per_request: 256,
  /**
   * Max stored wraps per vault, across every signed wrap set (sets are immutable
   * and kept), for owner-authored device-adding events and voluntary rekeys. A
   * rekey that clears `rekey_required` and a recovery-authored device_add are
   * exempt, so the cap can never leave a vault stuck in `rekey_required` or lock
   * out recovery; both are still bounded by membership_events_per_vault x
   * wraps_per_request.
   */
  wraps_per_vault: 20_000,
  /**
   * Per device, per vault, per rate window, applied to each of two budgets:
   * requests that pass authorization, and requests the vault's Durable Object
   * refuses at authorization of an existing vault.
   */
  rate_requests_per_window: 120,
  /**
   * Per account, per vault, per rate window: requests by a not-yet-enrolled device
   * on the recovery-identity path (`GET /recovery`, `GET /membership` with
   * `AKV-Device-Key`) whose proof verifies, whatever device ID the token names.
   * Counted on top of the per-device budgets above.
   */
  recovery_identity_requests_per_window: 30,
  rate_window_seconds: 60,
  /** Idempotency records are kept this long. */
  idempotency_ttl_seconds: 24 * 60 * 60,
  /** Max length of an Idempotency-Key header. */
  idempotency_key_max_length: 128,
  /** Accepted clock skew for token and proof time claims. */
  clock_skew_seconds: 60,
  /** Single-use window for a proof `jti` per device. */
  proof_jti_ttl_seconds: 120,
} as const;

/**
 * Remote-access limits (spec §9.6, §9.7, §10). `GET /v1/meta` publishes them
 * beside `LIMITS` only where remote access is enabled, so a writer sends the
 * `name_tag` wrapper only when it sees `lookup_tags_max`.
 */
export const REMOTE_ACCESS_LIMITS = {
  /** Max UTF-8 bytes of one relay text frame. */
  relay_frame_max_bytes: 131_072,
  /** The device's `hello` must arrive this soon after the upgrade. */
  relay_hello_timeout_ms: 10_000,
  /** Max outstanding calls per device connection. */
  relay_calls_inflight_per_device: 4,
  /** Max open relay connections per account. */
  relay_devices_per_account: 8,
  /** Max `reauth` frames per token lifetime of one connection (more closes it 4429). */
  relay_reauth_per_token_lifetime: 3,
  /** Time a device has to answer a call; `run` gets its own. */
  relay_call_deadline_ms: 60_000,
  relay_run_deadline_ms: 120_000,
  /**
   * Max sealed operations held per vault: pending ones plus acknowledged ones whose
   * ID is kept until `sealed_ttl_s` to refuse a replay.
   */
  sealed_queue_max: 256,
  /** A sealed operation is dropped this long after its `ts`. */
  sealed_ttl_s: 7 * 24 * 60 * 60,
  /** `GET /sealed` page size (default and maximum). */
  sealed_page_max: 50,
  /** Max `(tag, key_epoch)` pairs per `GET /lookup`. */
  lookup_tags_max: 8,
  /** MCP call budgets per minute, per (account, client), per (account, client) for `run`, and per account. */
  mcp_calls_per_minute_per_client: 60,
  mcp_run_calls_per_minute_per_client: 10,
  mcp_calls_per_minute_per_account: 300,
  /** `secrets_prepare_write` calls per minute per (account, client), on top of the general budgets. */
  mcp_prepare_write_per_minute_per_client: 6,
  /** Human write requests (spec §3.10): default and maximum lifetime, and the shortest a client may ask for. */
  write_request_ttl_s: 10 * 60,
  write_request_min_ttl_s: 60,
  /** A closed or expired request keeps its status row (never its ciphertext) this long, then is purged. */
  write_request_retention_s: 24 * 60 * 60,
  /** Open requests, and rows (open plus retained), per account in one vault. */
  write_requests_pending_per_account: 8,
  /** Open requests one MCP client of an account may hold in one vault, so a single client cannot take every slot. */
  write_requests_pending_per_client: 4,
  write_requests_retained_per_account: 64,
} as const;

export const PROTOCOL_VERSIONS = ['akv1'] as const;

/** Worker build version reported by `/healthz` and `/v1/meta`. */
export const WORKER_VERSION = '0.1.0';

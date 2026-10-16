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
   * requests that pass authorization, and requests refused before or during it.
   */
  rate_requests_per_window: 120,
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

export const PROTOCOL_VERSIONS = ['akv1'] as const;

/** Worker build version reported by `/healthz` and `/v1/meta`. */
export const WORKER_VERSION = '0.1.0';

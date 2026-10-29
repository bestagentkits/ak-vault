/**
 * Membership log storage. Every append re-verifies the whole chain from genesis
 * with `verifyMembershipChain` (the protocol library has no resumable verifier),
 * pinned to the stored trust anchor. The derived state is cached in memory and in
 * the `meta` table so reads and auth never replay the chain.
 */
import { cjson, membershipEventHash, parseJson, verifyMembershipChain, type MembershipEvent, type MembershipState } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';

const STATE_KEY = 'membership_state';

function predatesCurrentRevision(state: MembershipState): boolean {
  const removals = (state as { removals?: unknown }).removals;
  if (!Array.isArray(removals)) return true;
  return removals.some((r) => typeof (r as { log_head?: unknown } | null)?.log_head !== 'string');
}

export class MembershipStore {
  private cached: MembershipState | null | undefined;

  constructor(private readonly sql: SqlStorage) {}

  /** Current verified state, or null when the vault has no genesis yet. */
  state(): MembershipState | null {
    if (this.cached !== undefined) return this.cached;
    const row = this.sql.exec<{ v: string }>('SELECT v FROM meta WHERE k = ?', STATE_KEY).toArray()[0];
    const state = row ? (JSON.parse(row.v) as MembershipState) : null;
    // A vault created before the signed-wrap-set / removal-fence revision has a
    // state without `removals` and a chain that no longer verifies. Refuse every
    // request to it instead of serving it half-working (see the runbook).
    // A vault from before the removal `log_head` revision stored removals without
    // it, and its chain no longer verifies either: refuse it the same way.
    if (state !== null && predatesCurrentRevision(state)) {
      throw new ApiError('unsupported_version', { message: 'vault predates the current protocol revision' });
    }
    // A state stored before the role fence revision lacks `role_changes` and the
    // removals' `role` and `kind` until the next append re-derives it from the
    // chain. The Worker reads none of them; re-verify the chain before relying on them.
    this.cached = state;
    return this.cached;
  }

  requireState(): MembershipState {
    const state = this.state();
    if (!state) throw new ApiError('not_found');
    return state;
  }

  /** Verify a genesis event on its own (no stored chain). */
  static verifyGenesis(event: unknown, vaultId: string): MembershipState {
    const state = verifyMembershipChain([event], { vaultId });
    return state;
  }

  /** Verify `event` as the next event of the stored chain; returns the resulting state without persisting. */
  verifyAppend(event: unknown): MembershipState {
    const current = this.requireState();
    // The type is only trusted after chain verification below; claiming `rekey` here
    // just selects the looser bound, and the event must still verify as a rekey.
    const requiredRekey = current.rekey_required && (event as { type?: unknown } | null)?.type === 'rekey';
    const lastSeq = LIMITS.membership_events_per_vault - (requiredRekey ? 1 : 2);
    if (current.seq + 1 > lastSeq) throw new ApiError('quota_exceeded', { status: 403 });
    return verifyMembershipChain([...this.chain(), event], { vaultId: current.vault_id, trustedAnchor: current.trust_anchor });
  }

  /** Every stored event, genesis first (for verifiers that replay the chain). */
  chain(): unknown[] {
    return this.sql.exec<{ event_json: string }>('SELECT event_json FROM membership_events ORDER BY seq').toArray().map((r) => parseJson(r.event_json));
  }

  /** Persist a verified event and its resulting state (caller holds the transaction). */
  persist(event: MembershipEvent, next: MembershipState): void {
    this.sql.exec('INSERT INTO membership_events (seq, hash, event_json) VALUES (?, ?, ?)', event.seq, membershipEventHash(event), cjson(event));
    this.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v', STATE_KEY, JSON.stringify(next));
    this.cached = next;
  }

  /** Drop the in-memory cache (after a rolled-back transaction). */
  invalidate(): void {
    this.cached = undefined;
  }

  eventHash(seq: number): string | undefined {
    return this.sql.exec<{ hash: string }>('SELECT hash FROM membership_events WHERE seq = ?', seq).toArray()[0]?.hash;
  }

  page(from: number, limit: number): unknown[] {
    return this.sql
      .exec<{ event_json: string }>('SELECT event_json FROM membership_events WHERE seq >= ? ORDER BY seq LIMIT ?', from, limit)
      .toArray()
      .map((r) => JSON.parse(r.event_json) as unknown);
  }
}

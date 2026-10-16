/**
 * Point-in-time recovery of one vault object, behind the operator route
 * (`routes/operator-restore.ts`). Wraps the Durable Object SQLite PITR API
 * (`getCurrentBookmark`, `getBookmarkForTime`, `onNextSessionRestoreBookmark`);
 * the caller restarts the object afterwards so the restore takes effect.
 *
 * A restore is compare-and-swap on the object's current bookmark: the operator
 * names the bookmark it read just before, and any write since (or an earlier
 * restore, which moves the history forward) refuses it with `conflict`. That
 * is meant to make a replayed restore request a refusal; that a restore moves the
 * current bookmark is to be checked on staging, not locally (local workerd has no history).
 *
 * Platform errors carry text from the storage layer; they are mapped to fixed
 * messages and never echoed.
 */
import { ApiError } from '../http/errors.js';

/** The subset of `DurableObjectStorage` this module needs (a fake in tests). */
export interface PointInTimeStorage {
  getCurrentBookmark(): Promise<string>;
  getBookmarkForTime(timestamp: number | Date): Promise<string>;
  onNextSessionRestoreBookmark(bookmark: string): Promise<string>;
}

/** Durable Object bookmarks are short strings of hex digits and dashes. */
export const BOOKMARK_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;

/** Point-in-time history covers the past 30 days. */
export const PITR_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export function isBookmark(value: unknown): value is string {
  return typeof value === 'string' && BOOKMARK_PATTERN.test(value);
}

function refused(): ApiError {
  return new ApiError('bad_request', { message: 'point-in-time recovery refused the request' });
}

/** Run a storage PITR call; any platform failure becomes a fixed-message refusal. */
async function pitr<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch {
    throw refused();
  }
}

function checkedBookmark(value: unknown): string {
  // A value the platform returns that does not look like a bookmark is not passed on.
  if (!isBookmark(value)) throw new ApiError('internal');
  return value;
}

export async function currentBookmark(storage: PointInTimeStorage): Promise<string> {
  return checkedBookmark(await pitr(() => storage.getCurrentBookmark()));
}

/** Approximate: the platform may resolve earlier than `atMs` (see the runbook). */
export async function bookmarkForTime(storage: PointInTimeStorage, atMs: number, nowMs: number): Promise<string> {
  if (!Number.isSafeInteger(atMs) || atMs > nowMs || atMs < nowMs - PITR_WINDOW_MS) throw new ApiError('bad_request');
  return checkedBookmark(await pitr(() => storage.getBookmarkForTime(atMs)));
}

/**
 * Schedule a restore to `target` if the object is still at `expectedCurrent`.
 * Returns the undo bookmark (the point just before the restore). The restore
 * applies when the object next starts; the caller must restart it, and
 * `markPending` runs before the platform call (and is never undone) so the
 * caller refuses every request until that restart.
 */
export async function scheduleRestore(storage: PointInTimeStorage, target: string, expectedCurrent: string, markPending: () => void): Promise<string> {
  if (!isBookmark(target) || !isBookmark(expectedCurrent)) throw new ApiError('bad_request');
  const current = await currentBookmark(storage);
  if (current !== expectedCurrent) throw new ApiError('conflict', { message: 'the vault changed since the bookmark was read' });
  markPending();
  // From here the restore may be scheduled even if the call throws, so the object
  // stays pending (refusing requests) until it restarts: at worst one needless restart.
  return checkedBookmark(await pitr(() => storage.onNextSessionRestoreBookmark(target)));
}

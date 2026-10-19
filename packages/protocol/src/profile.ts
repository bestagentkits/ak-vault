/**
 * Item profile layout and provenance (spec §5.1). A profile lives inside the
 * item ciphertext as `meta.profile`: a closed set of keys, each a field object
 * `{value, by, at, src}`. Profile text is inert, author-attributed data; it
 * never creates or widens a grant.
 */
import { cjson, type JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import { asArray, asEnum, asId, asInt, asObject, asWellFormed, exactKeys } from './validate.js';

export const PROFILE_TEXT_KEYS = {
  description: 1024,
  when_to_use: 1024,
  when_not_to_use: 1024,
  provider: 128,
  account: 128,
  environment: 128,
  owner: 128,
} as const;
export const PROFILE_LIST_KEYS = ['projects', 'tags', 'permissions', 'aliases', 'usage_hosts'] as const;
export const PROFILE_KINDS = ['api_key', 'token', 'password', 'private_key', 'certificate', 'connection_string', 'webhook_secret', 'client_secret', 'other'] as const;
export const PROFILE_SENSITIVITIES = ['normal', 'high'] as const;
export const PROFILE_SOURCES = ['local', 'import'] as const;
export const PROFILE_KEYS = [...Object.keys(PROFILE_TEXT_KEYS), ...PROFILE_LIST_KEYS, 'kind', 'sensitivity', 'expires_at', 'rotate_url'].sort() as ProfileKey[];

export const MAX_PROFILE_LIST_ITEMS = 32;
export const MAX_PROFILE_LIST_ITEM = 64;
export const MAX_ROTATE_URL = 512;

export type ProfileKey =
  | keyof typeof PROFILE_TEXT_KEYS
  | (typeof PROFILE_LIST_KEYS)[number]
  | 'kind'
  | 'sensitivity'
  | 'expires_at'
  | 'rotate_url';
export type ProfileSource = (typeof PROFILE_SOURCES)[number];
/** How a receiver shows a field: its own `src`, or `sync` (written by another device, untrusted). */
export type ProfileOrigin = ProfileSource | 'sync';

export interface ProfileField {
  value: string | string[];
  by: string;
  at: number;
  src: ProfileSource;
}

export type Profile = Partial<Record<ProfileKey, ProfileField>>;

// C0, DEL, C1, the Arabic letter mark, zero-width space/non-joiner/joiner,
// LRM/RLM, bidi embeddings/overrides/isolates, line and paragraph separators,
// and the byte order mark (zero-width no-break space).
const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff]/;
const EXPIRES_AT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

/** Profile text rule (spec §5.1): non-empty, at most `limit` code points, no control or bidi characters. */
export function asProfileText(value: unknown, what: string, limit: number): string {
  if (typeof value !== 'string') fail('bad_request', `${what} must be text`);
  asWellFormed(value, what);
  const points = [...value].length;
  if (points < 1 || points > limit) fail('bad_request', `${what} must be 1..${limit} code points`);
  if (FORBIDDEN.test(value)) fail('bad_request', `${what} contains a forbidden character`);
  return value;
}

function asList(value: unknown, what: string): string[] {
  const list = asArray(value, what, MAX_PROFILE_LIST_ITEMS);
  if (list.length < 1) fail('bad_request', `${what} must have 1..${MAX_PROFILE_LIST_ITEMS} items`);
  const items = list.map((item, i) => {
    const text = asProfileText(item, `${what}[${i}]`, MAX_PROFILE_LIST_ITEM);
    if (text.includes(',')) fail('bad_request', `${what}[${i}] contains a comma`);
    return text;
  });
  if (new Set(items).size !== items.length) fail('bad_request', `${what} contains duplicates`);
  return items;
}

function asExpiresAt(value: unknown, what: string): string {
  const text = asProfileText(value, what, 20);
  const m = EXPIRES_AT.exec(text);
  if (!m) fail('bad_request', `${what} must be YYYY-MM-DDTHH:MM:SSZ`);
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number) as [number, number, number, number, number, number];
  const days = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (mo < 1 || mo > 12 || d < 1 || d > days || h > 23 || mi > 59 || s > 59) fail('bad_request', `${what} is not a valid UTC time`);
  return text;
}

/** Validate one profile `value` by its key's rule (`bad_request`). */
export function parseProfileValue(key: ProfileKey, value: unknown, what: string): string | string[] {
  if (key in PROFILE_TEXT_KEYS) return asProfileText(value, what, PROFILE_TEXT_KEYS[key as keyof typeof PROFILE_TEXT_KEYS]);
  if ((PROFILE_LIST_KEYS as readonly string[]).includes(key)) return asList(value, what);
  switch (key) {
    case 'kind':
      return asEnum(value, PROFILE_KINDS, what);
    case 'sensitivity':
      return asEnum(value, PROFILE_SENSITIVITIES, what);
    case 'expires_at':
      return asExpiresAt(value, what);
    default: {
      const url = asProfileText(value, what, MAX_ROTATE_URL);
      if (!url.startsWith('https://')) fail('bad_request', `${what} must start with https://`);
      return url;
    }
  }
}

/** Validate an untrusted profile object (`bad_request` on any violation). Returns a copy. */
export function validateProfile(value: unknown, what = 'profile'): Profile {
  const obj = asObject(value, what);
  const out: Profile = {};
  for (const key of Object.keys(obj).sort()) {
    if (!(PROFILE_KEYS as string[]).includes(key)) fail('bad_request', `${what} has an unknown key`);
    const field = asObject(obj[key], `${what}.${key}`);
    exactKeys(field, ['value', 'by', 'at', 'src'], `${what}.${key}`);
    out[key as ProfileKey] = {
      value: parseProfileValue(key as ProfileKey, field['value'], `${what}.${key}.value`),
      by: asId(field['by'], `${what}.${key}.by`),
      at: asInt(field['at'], `${what}.${key}.at`),
      src: asEnum(field['src'], PROFILE_SOURCES, `${what}.${key}.src`),
    };
  }
  return out;
}

function sameValue(a: string | string[], b: string | string[]): boolean {
  return cjson(a) === cjson(b);
}

export interface ProfileRecordContext {
  author: string;
  ts: number;
  base_revision: number;
}

export interface CheckedProfile {
  /** The fields that passed, in key order. */
  profile: Profile;
  /** Keys dropped for broken provenance (audit `profile_provenance_invalid`), in key order. */
  dropped: ProfileKey[];
  /** How each kept field is shown. */
  origins: Partial<Record<ProfileKey, ProfileOrigin>>;
}

/**
 * Check `next` (the profile of `record`) against `prev`, the validated profile
 * at `record.base_revision` (an empty profile for a tombstone), or `null` when
 * the device does not hold that revision. A create (`base_revision` 0) is
 * always checked against an empty profile. An unchanged field must be
 * byte-identical to `prev`; a new or changed one must carry `by` =
 * `record.author` and `at` = `record.ts`. Breaking fields are dropped.
 *
 * Origins are transitive, so only this device's own write history yields its
 * own label. A kept field shows its `src` only when `by` is `selfDeviceId` and
 * either this record changed it and `record.author` is `selfDeviceId`, or it is
 * carried unchanged from a held `prev` whose stored origin (`prevOrigins`: the
 * `origins` this check returned when the device accepted `prev`) is that same
 * `src`. Every other field, and every field when `prev` is `null`, is `sync`.
 */
export function checkProfileProvenance(
  prev: unknown,
  next: unknown,
  record: ProfileRecordContext,
  opts: { selfDeviceId?: string; prevOrigins?: Partial<Record<ProfileKey, ProfileOrigin>> | null } = {},
): CheckedProfile {
  const author = asId(record.author, 'record.author');
  const ts = asInt(record.ts, 'record.ts');
  const base = asInt(record.base_revision, 'record.base_revision');
  const nextProfile = validateProfile(next, 'next profile');
  const prevProfile: Profile | null = base === 0 ? {} : prev === null ? null : validateProfile(prev, 'prev profile');
  const self = opts.selfDeviceId;
  const prevOrigins = base === 0 ? null : (opts.prevOrigins ?? null);
  const out: CheckedProfile = { profile: {}, dropped: [], origins: {} };
  for (const key of Object.keys(nextProfile) as ProfileKey[]) {
    const field = nextProfile[key]!;
    let ok = true;
    let carried = false;
    if (prevProfile !== null) {
      const before = prevProfile[key];
      carried = before !== undefined && sameValue(before.value, field.value);
      ok = carried ? cjson(before) === cjson(field) : field.by === author && field.at === ts;
    }
    if (!ok) {
      out.dropped.push(key);
      continue;
    }
    out.profile[key] = field;
    let own = false;
    if (self !== undefined && field.by === self && prevProfile !== null) {
      own = carried ? prevOrigins !== null && Object.prototype.hasOwnProperty.call(prevOrigins, key) && prevOrigins[key] === field.src : author === self;
    }
    out.origins[key] = own ? field.src : 'sync';
  }
  return out;
}

/**
 * Writer side: build the profile for a new record from `prev` (the head's
 * validated profile, `{}` for a create) and `changes` (a key mapped to its new
 * value, or `null` to remove the field). An unchanged value keeps the prior
 * field byte for byte; a changed one is attributed to the writing device.
 */
export function buildNextProfile(
  prev: Profile,
  changes: Partial<Record<ProfileKey, string | string[] | null>>,
  writer: { deviceId: string; ts: number; src: ProfileSource },
): Profile {
  const base = validateProfile(prev, 'prev profile');
  const draft: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(changes)) {
    if (value === undefined) continue;
    if (value === null) {
      delete draft[key];
      continue;
    }
    const before = base[key as ProfileKey];
    draft[key] = before && sameValue(before.value, value) ? before : { value, by: writer.deviceId, at: writer.ts, src: writer.src };
  }
  return validateProfile(draft, 'next profile');
}

const POLICY_META_KEYS = new Set(['kind', 'item_ids', 'policy', 'profile']);
const PROFILE_KEY_FOLDS = new Set(PROFILE_KEYS.map((k) => k.replace(/_/g, '')));

/**
 * The unknown `meta` keys a writer may carry forward from the previous head
 * (spec §5.1): never `kind`, `item_ids`, `policy` or `profile` (written
 * separately), nor any key that folds (lowercased, `_`, `-`, `.` removed) to a
 * profile key, so legacy profile spellings are dropped rather than re-signed.
 */
export function carryForwardMeta(meta: JsonObject): JsonObject {
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(meta)) {
    if (POLICY_META_KEYS.has(key) || PROFILE_KEY_FOLDS.has(key.toLowerCase().replace(/[_.-]/g, ''))) continue;
    out[key] = value;
  }
  return out;
}

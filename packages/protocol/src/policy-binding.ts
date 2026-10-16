/**
 * Policy binding (spec §8): which portable policy items cap which item.
 *
 * A policy item is an item whose payload has `meta.kind === "policy"`. Its
 * payload is `{"name", "value":"", "meta":{"kind":"policy","item_ids":[…],"policy":{…}}, "sensitivity"}`:
 * `item_ids` names the items it governs by opaque item ID, `policy` is the §8
 * policy object, and the payload `sensitivity` is the minimum sensitivity it
 * imposes on every governed item. All of it is inside the item ciphertext, so
 * the server never learns which item a policy governs.
 *
 * `resolveItemPolicy` combines every policy that governs one target item into
 * a single §8 policy object (intersection) plus the effective sensitivity; the
 * caller then evaluates `effectiveGrant(local, policy, sensitivity)`. Anything
 * the device cannot verify, parse or disambiguate throws, and the caller
 * refuses release: a binding can only narrow, never widen.
 */
import { fail } from './errors.js';
import { parseItemPayload, type ItemPayload, type Sensitivity } from './item.js';
import { parsePolicy, type PortablePolicy } from './policy.js';
import { asArray, asBool, asId, asIdList, asObject, exactKeys } from './validate.js';

/** `meta.kind` of a policy item. */
export const POLICY_ITEM_KIND = 'policy';
/** Most item IDs one policy item may govern. */
export const MAX_POLICY_ITEM_IDS = 1024;
/** Most items and conflict branches per item a resolution accepts. */
export const MAX_RESOLVE_ITEMS = 1_000_000;
export const MAX_RESOLVE_BRANCHES = 4096;

/** One decrypted record of an item: its head or an unresolved conflict branch. */
export interface PolicyResolutionEntry {
  tombstone: boolean;
  /** The decrypted payload object, or `null` when the device could not open the record. */
  payload: unknown;
}

/** An item as the device holds it: the current head and every unresolved conflict branch. */
export interface PolicyResolutionItem {
  item_id: string;
  head: PolicyResolutionEntry;
  branches: PolicyResolutionEntry[];
}

/** The rule fields of a §8 policy object (no free text). */
export interface PolicyRules {
  max_ttl_s?: number;
  require_approval?: boolean;
  allowed_projects?: string[];
  allowed_purposes?: string[];
  deny_agents?: string[];
}

export interface ResolvedItemPolicy {
  /** Intersection of every governing policy; `null` when none governs the item. */
  policy: PolicyRules | null;
  /** `high` when the item or any governing policy item is `high`. */
  sensitivity: Sensitivity;
}

export interface PolicyItem {
  item_ids: string[];
  policy: PortablePolicy;
}

/** True when a validated live payload is a policy item (`meta.kind === "policy"`). */
export function isPolicyPayload(payload: ItemPayload): boolean {
  return payload.meta['kind'] === POLICY_ITEM_KIND;
}

/**
 * Validate the policy-item layout of a live payload whose `meta.kind` is
 * `"policy"` (`bad_request` otherwise): `value` is `""`, `meta` has exactly
 * `kind`, `item_ids` (1..1024 unique IDs, never the policy's own `itemId`) and
 * `policy` (parsed by `parsePolicy`).
 */
export function parsePolicyItem(itemId: string, payload: ItemPayload): PolicyItem {
  asId(itemId, 'item_id');
  if (!isPolicyPayload(payload)) fail('bad_request', 'item is not a policy item');
  if (payload.value !== '') fail('bad_request', 'policy item value must be empty');
  exactKeys(payload.meta, ['kind', 'item_ids', 'policy'], 'policy item meta');
  const itemIds = asIdList(payload.meta['item_ids'], 'policy item meta.item_ids', MAX_POLICY_ITEM_IDS);
  if (itemIds.length === 0) fail('bad_request', 'policy item governs no item');
  if (itemIds.includes(itemId)) fail('bad_request', 'policy item names itself');
  return { item_ids: itemIds, policy: parsePolicy(payload.meta['policy']) };
}

interface Entry {
  tombstone: boolean;
  payload: unknown;
}

function parseEntry(value: unknown, what: string): Entry {
  const obj = asObject(value, what);
  exactKeys(obj, ['tombstone', 'payload'], what);
  const tombstone = asBool(obj['tombstone'], `${what}.tombstone`);
  const payload = obj['payload'];
  if (payload !== null) asObject(payload, `${what}.payload`);
  return { tombstone, payload };
}

interface Item {
  item_id: string;
  head: Entry;
  branches: Entry[];
}

function parseItems(value: unknown): Item[] {
  const items = asArray(value, 'items', MAX_RESOLVE_ITEMS).map((raw, i): Item => {
    const what = `items[${i}]`;
    const obj = asObject(raw, what);
    exactKeys(obj, ['item_id', 'head', 'branches'], what);
    return {
      item_id: asId(obj['item_id'], `${what}.item_id`),
      head: parseEntry(obj['head'], `${what}.head`),
      branches: asArray(obj['branches'], `${what}.branches`, MAX_RESOLVE_BRANCHES).map((b, j) => parseEntry(b, `${what}.branches[${j}]`)),
    };
  });
  if (new Set(items.map((x) => x.item_id)).size !== items.length) fail('bad_request', 'items contains a duplicate item_id');
  return items;
}

/** Keep the first occurrence of each string, in order. */
function unique(list: Iterable<string>): string[] {
  return [...new Set(list)];
}

function intersect(acc: string[] | undefined, next: string[] | undefined): string[] | undefined {
  if (next === undefined) return acc;
  const keep = new Set(next);
  return unique((acc ?? next).filter((x) => keep.has(x)));
}

function combine(policies: PortablePolicy[]): PolicyRules {
  const rules: PolicyRules = {};
  for (const p of policies) {
    if (p.max_ttl_s !== undefined) rules.max_ttl_s = rules.max_ttl_s === undefined ? p.max_ttl_s : Math.min(rules.max_ttl_s, p.max_ttl_s);
    if (p.require_approval !== undefined) rules.require_approval = rules.require_approval === true || p.require_approval;
    const projects = intersect(rules.allowed_projects, p.allowed_projects);
    if (projects !== undefined) rules.allowed_projects = projects;
    const purposes = intersect(rules.allowed_purposes, p.allowed_purposes);
    if (purposes !== undefined) rules.allowed_purposes = purposes;
    if (p.deny_agents !== undefined) rules.deny_agents = unique([...(rules.deny_agents ?? []), ...p.deny_agents]);
  }
  return rules;
}

/**
 * Resolve the policies that govern `targetItemId` from every item the device
 * holds. Checks, in order (the first failure is the result):
 * 1. shape: `targetItemId` is an ID; `items` is a list of
 *    `{item_id, head, branches}` with unique IDs and entries `{tombstone, payload}`,
 *    `payload` an object or `null` (`bad_request`);
 * 2. any entry with `payload: null` (the device could not open it, so it may be
 *    a policy governing the target) → `decrypt_failed`;
 * 3. every payload parses as an item payload for its `tombstone` flag (`bad_request`);
 * 4. every live policy payload parses as a policy item (`bad_request`);
 * 5. the target is present, its head is live, and neither its head nor any
 *    branch is a policy item (`bad_request`);
 * 6. an item with unresolved conflict branches whose head or any branch is a
 *    live policy naming the target → `conflict`.
 * Then every other item whose live head is a policy naming the target governs
 * it, combined by intersection in `item_id` byte order.
 */
export function resolveItemPolicy(targetItemId: string, items: unknown): ResolvedItemPolicy {
  const target = asId(targetItemId, 'target item_id');
  const list = parseItems(items);
  for (const item of list) {
    for (const entry of [item.head, ...item.branches]) if (entry.payload === null) fail('decrypt_failed', 'an item could not be opened');
  }
  const parsed = list.map((item) => {
    const open = (e: Entry): ItemPayload | null => {
      const payload = parseItemPayload(e.payload, e.tombstone);
      return 'deleted' in payload ? null : payload;
    };
    return { item_id: item.item_id, head: open(item.head), branches: item.branches.map(open), hasBranches: item.branches.length > 0 };
  });
  const bindings = parsed.map((item) => {
    const bind = (p: ItemPayload | null) => (p !== null && isPolicyPayload(p) ? { payload: p, binding: parsePolicyItem(item.item_id, p) } : null);
    return { ...item, headPolicy: bind(item.head), branchPolicies: item.branches.map(bind) };
  });

  const own = bindings.find((x) => x.item_id === target);
  if (own === undefined || own.head === null) fail('bad_request', 'target item is not a live item');
  if (own.headPolicy !== null || own.branchPolicies.some((b) => b !== null)) fail('bad_request', 'target item is a policy item');
  const live = [own.head, ...own.branches].filter((p): p is ItemPayload => p !== null);
  let sensitivity: Sensitivity = live.some((p) => p.sensitivity === 'high') ? 'high' : 'normal';

  const governing: PortablePolicy[] = [];
  const others = bindings.filter((x) => x.item_id !== target).sort((a, b) => (a.item_id < b.item_id ? -1 : a.item_id > b.item_id ? 1 : 0));
  for (const item of others) {
    const names = (b: typeof item.headPolicy) => b !== null && b.binding.item_ids.includes(target);
    if (item.hasBranches) {
      if (names(item.headPolicy) || item.branchPolicies.some(names)) fail('conflict', 'a policy governing the item has an unresolved conflict');
      continue;
    }
    const head = item.headPolicy;
    if (head === null || !names(head)) continue;
    governing.push(head.binding.policy);
    if (head.payload.sensitivity === 'high') sensitivity = 'high';
  }
  return { policy: governing.length === 0 ? null : combine(governing), sensitivity };
}

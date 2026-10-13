/**
 * Portable policy (spec §8): restrictive maxima only. Effective grant =
 * local grant ∩ policy; a policy can never widen a local grant, a missing
 * field adds no restriction, and `sensitivity:"high"` always requires approval.
 * Free-text fields (`description`, `when_to_use`, `urls`) are returned verbatim
 * as inert, untrusted data and never influence the grant.
 */
import { fail } from './errors.js';
import type { Sensitivity } from './item.js';
import { SENSITIVITIES } from './item.js';
import { asArray, asBool, asEnum, asInt, asObject, asString, exactKeys } from './validate.js';

export interface LocalGrant {
  ttl_s: number;
  require_approval: boolean;
  projects: string[];
  purposes: string[];
  agents: string[];
}

export interface PortablePolicy {
  max_ttl_s?: number;
  require_approval?: boolean;
  allowed_projects?: string[];
  allowed_purposes?: string[];
  deny_agents?: string[];
  /** Untrusted author-supplied text; display only, never interpreted. */
  untrusted_text: { description?: string; when_to_use?: string; urls?: string[] };
}

const POLICY_FIELDS = ['max_ttl_s', 'require_approval', 'allowed_projects', 'allowed_purposes', 'deny_agents'] as const;
const TEXT_FIELDS = ['description', 'when_to_use', 'urls'] as const;

function asStringList(value: unknown, what: string): string[] {
  return asArray(value, what, 1024).map((v, i) => asString(v, `${what}[${i}]`, 256, 1));
}

/** Parse an untrusted policy object; unknown fields are `bad_request` (fail closed). */
export function parsePolicy(value: unknown): PortablePolicy {
  const obj = asObject(value, 'policy');
  exactKeys(obj, [], 'policy', [...POLICY_FIELDS, ...TEXT_FIELDS]);
  const policy: PortablePolicy = { untrusted_text: {} };
  if (obj['max_ttl_s'] !== undefined) policy.max_ttl_s = asInt(obj['max_ttl_s'], 'policy.max_ttl_s');
  if (obj['require_approval'] !== undefined) policy.require_approval = asBool(obj['require_approval'], 'policy.require_approval');
  if (obj['allowed_projects'] !== undefined) policy.allowed_projects = asStringList(obj['allowed_projects'], 'policy.allowed_projects');
  if (obj['allowed_purposes'] !== undefined) policy.allowed_purposes = asStringList(obj['allowed_purposes'], 'policy.allowed_purposes');
  if (obj['deny_agents'] !== undefined) policy.deny_agents = asStringList(obj['deny_agents'], 'policy.deny_agents');
  if (obj['description'] !== undefined) policy.untrusted_text.description = asString(obj['description'], 'policy.description', 8192);
  if (obj['when_to_use'] !== undefined) policy.untrusted_text.when_to_use = asString(obj['when_to_use'], 'policy.when_to_use', 8192);
  if (obj['urls'] !== undefined) policy.untrusted_text.urls = asArray(obj['urls'], 'policy.urls', 64).map((v, i) => asString(v, `policy.urls[${i}]`, 2048));
  return policy;
}

function parseLocalGrant(value: unknown): LocalGrant {
  const obj = asObject(value, 'local grant');
  exactKeys(obj, ['ttl_s', 'require_approval', 'projects', 'purposes', 'agents'], 'local grant');
  return {
    ttl_s: asInt(obj['ttl_s'], 'local grant.ttl_s'),
    require_approval: asBool(obj['require_approval'], 'local grant.require_approval'),
    projects: asStringList(obj['projects'], 'local grant.projects'),
    purposes: asStringList(obj['purposes'], 'local grant.purposes'),
    agents: asStringList(obj['agents'], 'local grant.agents'),
  };
}

/**
 * Narrow a device-local grant by a portable policy (`null` = no policy).
 * The result is always a subset of `localGrant`.
 */
export function effectiveGrant(localGrant: LocalGrant, policy: unknown, sensitivity: Sensitivity): LocalGrant {
  const local = parseLocalGrant(localGrant);
  const level = asEnum(sensitivity, SENSITIVITIES, 'sensitivity');
  const p: PortablePolicy = policy === null || policy === undefined ? { untrusted_text: {} } : parsePolicy(policy);
  const within = (list: string[], allowed: string[] | undefined) => (allowed === undefined ? [...list] : list.filter((x) => allowed.includes(x)));
  const grant: LocalGrant = {
    ttl_s: p.max_ttl_s === undefined ? local.ttl_s : Math.min(local.ttl_s, p.max_ttl_s),
    require_approval: local.require_approval || p.require_approval === true || level === 'high',
    projects: within(local.projects, p.allowed_projects),
    purposes: within(local.purposes, p.allowed_purposes),
    agents: local.agents.filter((a) => !(p.deny_agents ?? []).includes(a)),
  };
  // Defensive invariant: narrowing only.
  if (grant.ttl_s > local.ttl_s || (local.require_approval && !grant.require_approval)) fail('forbidden', 'policy attempted to widen a grant');
  return grant;
}

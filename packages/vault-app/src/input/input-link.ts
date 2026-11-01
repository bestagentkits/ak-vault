/**
 * Input-request links (spec §3.11): `<origin>/input#r=<request_id>&v=<vault_id>&k=<input_pub>&n=<name>[&p=<purpose>]`.
 * The Worker redirects `/input` to `/app/` and the browser keeps the fragment.
 * IDs and the public input key are base64url; name and purpose are
 * percent-encoded. Parsing is exact: these keys only, each at most once, every
 * value well formed; anything else is no link at all. The name and purpose are
 * for display; the device that issued the key binds them in the seal's AAD.
 */
import { b64decodeLength, MAX_WRITE_PURPOSE } from '@ak-vault/protocol';
import { isOpaqueId } from '../sync/write-request.js';
import { validItemName, validMetaText } from '../sync/item-names.js';

export interface InputLink {
  requestId: string;
  vaultId: string;
  /** The device's one-time X25519 public key for this request, base64url (32 bytes). */
  inputPub: string;
  name: string;
  purpose: string | null;
}

const LINK_KEYS = new Set(['r', 'v', 'k', 'n', 'p']);
const PART = /^([a-z])=([^=&#]*)$/;

/**
 * True when a fragment is meant as an input link, well formed or not: one of its
 * `&`-separated parts starts with an input-link key. Such a fragment never reaches
 * the dashboard; it is parsed here and, if invalid, refused.
 */
export function isInputFragment(hash: string): boolean {
  return /(?:^#|&)[rvknp]=/.test(hash);
}

function isInputPub(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try {
    b64decodeLength(value, 32);
    return true;
  } catch {
    return false;
  }
}

function decodeText(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/** A purpose shown on the form: 1..200 UTF-16 units of text that renders as itself. */
export function validPurpose(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= MAX_WRITE_PURPOSE && validMetaText(value);
}

/** Validate an input link (from the fragment or from the pending sign-in); null when anything is off. */
export function checkInputLink(value: unknown): InputLink | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v).sort().join(',');
  if (keys !== 'inputPub,name,purpose,requestId,vaultId') return null;
  const { requestId, vaultId, inputPub, name, purpose } = v;
  if (typeof requestId !== 'string' || !isOpaqueId(requestId) || typeof vaultId !== 'string' || !isOpaqueId(vaultId)) return null;
  if (typeof inputPub !== 'string' || !isInputPub(inputPub) || !validItemName(name)) return null;
  if (purpose !== null && !validPurpose(purpose)) return null;
  return { requestId, vaultId, inputPub, name, purpose };
}

/** Parse `#r=…&v=…&k=…&n=…[&p=…]` exactly; anything else is null. */
export function parseInputLink(hash: string): InputLink | null {
  if (!hash.startsWith('#') || hash.length === 1) return null;
  const fields = new Map<string, string>();
  for (const part of hash.slice(1).split('&')) {
    const m = PART.exec(part);
    if (!m || !LINK_KEYS.has(m[1]!) || fields.has(m[1]!)) return null;
    const text = m[1] === 'n' || m[1] === 'p' ? decodeText(m[2]!) : m[2]!;
    if (text === null) return null;
    fields.set(m[1]!, text);
  }
  return checkInputLink({
    requestId: fields.get('r'),
    vaultId: fields.get('v'),
    inputPub: fields.get('k'),
    name: fields.get('n'),
    purpose: fields.has('p') ? fields.get('p') : null,
  });
}

/**
 * Item name and metadata text rules shared with the AgentKit CLI: a name is
 * non-empty, already trimmed, has no NUL or "/", is well-formed UTF-16, and has
 * no character that changes how text renders (C0/DEL/C1 controls, bidi
 * embeddings, overrides and isolates, U+2028/U+2029), so a name another device
 * wrote cannot pose as a different name in this list.
 */
import { MAX_ITEM_NAME, MAX_ITEM_VALUE } from '@ak-vault/protocol';

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// eslint-disable-next-line no-control-regex
const RENDER_CHANGING = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u2028\u2029]/;

export function isWellFormedText(text: string): boolean {
  return !LONE_SURROGATE.test(text);
}

export function validMetaText(text: string): boolean {
  return isWellFormedText(text) && !RENDER_CHANGING.test(text);
}

export function validItemName(name: unknown): name is string {
  return (
    typeof name === 'string' &&
    name !== '' &&
    name.length <= MAX_ITEM_NAME &&
    name.trim() === name &&
    !name.includes('/') &&
    validMetaText(name)
  );
}

/** A value the dashboard may store: well-formed text within the protocol bound (UTF-16 units). */
export function validItemValue(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_ITEM_VALUE && isWellFormedText(value);
}

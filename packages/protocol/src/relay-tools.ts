/**
 * Relay tool arguments and results (spec §9.7 "Tools"). Both are canonical JSON
 * objects with exact key sets. A device answers an invalid `args` object with
 * `invalid_args`; the Worker refuses one before relaying or sealing it. Every
 * failure here is `bad_request`.
 */
import { utf8Encode } from './bytes.js';
import { cjsonBytes, type JsonObject } from './canonical-json.js';
import { MAX_PLAINTEXT_BYTES } from './aead.js';
import { fail, isAkvError } from './errors.js';
import { parseInputSeal, type InputSealWire } from './input-seal.js';
import { SENSITIVITIES } from './item.js';
import { PROFILE_KEYS, asProfileText, parseProfileValue, type ProfileKey } from './profile.js';
import type { RelayTool } from './relay-frames.js';
import { MAX_ITEM_NAME, MAX_ITEM_VALUE } from './sealed-op.js';
import { asArray, asB64, asBool, asEnum, asId, asInt, asObject, asPrintableAscii, asString, asWellFormed, exactKeys, type Obj } from './validate.js';
import { MAX_WRITE_PURPOSE, WRITE_INTENT_OPERATIONS } from './write-intent.js';

export const SEARCH_FIELDS = ['name', 'description', 'provider', 'account', 'environment', 'projects', 'tags'] as const;
export const ENTRY_ORIGINS = ['local', 'import', 'sync'] as const;
const ENV_VAR = /^[A-Z_][A-Z0-9_]*$/;
const MAX_RESULT_ITEMS = 100;

function name(value: unknown, what: string): string {
  return asWellFormed(asString(value, what, MAX_ITEM_NAME, 1), what);
}

function bytesString(value: unknown, what: string, maxBytes: number, minBytes = 0): string {
  const text = asWellFormed(asString(value, what, maxBytes, minBytes), what);
  const n = utf8Encode(text).length;
  if (n < minBytes || n > maxBytes) fail('bad_request', `${what} must be ${minBytes}..${maxBytes} bytes`);
  return text;
}

function optional(obj: Obj, key: string, parse: (v: unknown) => unknown): void {
  if (obj[key] !== undefined) parse(obj[key]);
}

/** Validate `args` for `tool`; returns it unchanged. */
export function parseToolArgs(tool: RelayTool, value: unknown, what = 'args'): JsonObject {
  const obj = asObject(value, what);
  switch (tool) {
    case 'search': {
      exactKeys(obj, ['query'], what, ['fields', 'limit']);
      asProfileText(obj['query'], `${what}.query`, 200);
      optional(obj, 'fields', (v) => {
        const list = asArray(v, `${what}.fields`, SEARCH_FIELDS.length).map((f, i) => asEnum(f, SEARCH_FIELDS, `${what}.fields[${i}]`));
        if (list.length < 1 || new Set(list).size !== list.length) fail('bad_request', `${what}.fields must be a non-empty set`);
      });
      optional(obj, 'limit', (v) => asInt(v, `${what}.limit`, 1, 50));
      break;
    }
    case 'list':
      exactKeys(obj, [], what, ['cursor', 'limit']);
      optional(obj, 'cursor', (v) => bytesString(v, `${what}.cursor`, 256, 1));
      optional(obj, 'limit', (v) => asInt(v, `${what}.limit`, 1, 100));
      break;
    case 'describe':
    case 'delete':
      exactKeys(obj, ['name'], what);
      name(obj['name'], `${what}.name`);
      break;
    case 'set': {
      exactKeys(obj, ['name', 'value'], what, ['sensitivity']);
      name(obj['name'], `${what}.name`);
      asWellFormed(asString(obj['value'], `${what}.value`, MAX_ITEM_VALUE), `${what}.value`);
      optional(obj, 'sensitivity', (v) => asEnum(v, SENSITIVITIES, `${what}.sensitivity`));
      // The sealed operation must fit one AEAD plaintext, so every set is sealable.
      if (cjsonBytes({ op: 'set', ...obj }).length > MAX_PLAINTEXT_BYTES) fail('bad_request', `${what} is too large to seal`);
      break;
    }
    case 'request':
      exactKeys(obj, ['name', 'purpose'], what, ['project', 'ttl_s']);
      name(obj['name'], `${what}.name`);
      asProfileText(obj['purpose'], `${what}.purpose`, 200);
      optional(obj, 'project', (v) => asProfileText(v, `${what}.project`, 128));
      optional(obj, 'ttl_s', (v) => asInt(v, `${what}.ttl_s`, 1, 86_400));
      break;
    case 'run': {
      exactKeys(obj, ['argv', 'env'], what, ['cwd_project', 'timeout_s']);
      const argv = asArray(obj['argv'], `${what}.argv`, 64);
      if (argv.length < 1) fail('bad_request', `${what}.argv must not be empty`);
      argv.forEach((a, i) => asWellFormed(asString(a, `${what}.argv[${i}]`, Number.MAX_SAFE_INTEGER), `${what}.argv[${i}]`));
      const env = asArray(obj['env'], `${what}.env`, 16);
      if (env.length < 1) fail('bad_request', `${what}.env must not be empty`);
      const vars = env.map((e, i) => {
        const entry = asObject(e, `${what}.env[${i}]`);
        exactKeys(entry, ['var', 'name'], `${what}.env[${i}]`);
        const v = asPrintableAscii(entry['var'], `${what}.env[${i}].var`, 128, 1);
        if (!ENV_VAR.test(v)) fail('bad_request', `${what}.env[${i}].var is not an environment variable name`);
        name(entry['name'], `${what}.env[${i}].name`);
        return v;
      });
      if (new Set(vars).size !== vars.length) fail('bad_request', `${what}.env names a variable twice`);
      optional(obj, 'cwd_project', (v) => asProfileText(v, `${what}.cwd_project`, 128));
      optional(obj, 'timeout_s', (v) => asInt(v, `${what}.timeout_s`, 1, 110));
      break;
    }
    case 'request_input':
      exactKeys(obj, ['request_id', 'name', 'operation', 'expires_at'], what, ['purpose', 'sensitivity']);
      asId(obj['request_id'], `${what}.request_id`);
      name(obj['name'], `${what}.name`);
      optional(obj, 'purpose', (v) => asWellFormed(asString(v, `${what}.purpose`, MAX_WRITE_PURPOSE, 1), `${what}.purpose`));
      asEnum(obj['operation'], WRITE_INTENT_OPERATIONS, `${what}.operation`);
      optional(obj, 'sensitivity', (v) => asEnum(v, SENSITIVITIES, `${what}.sensitivity`));
      asInt(obj['expires_at'], `${what}.expires_at`);
      break;
    case 'input_deliver': {
      exactKeys(obj, ['request_id', 'sealed'], what);
      const requestId = asId(obj['request_id'], `${what}.request_id`);
      let sealed: InputSealWire;
      try {
        sealed = parseInputSeal(obj['sealed'], `${what}.sealed`);
      } catch (err) {
        // Every args refusal is bad_request (the device answers invalid_args), an unknown seal version included.
        if (isAkvError(err)) fail('bad_request', `${what}.sealed is not a valid input seal`);
        throw err;
      }
      if (sealed.request_id !== requestId) fail('bad_request', `${what}.sealed belongs to another request`);
      break;
    }
    default:
      fail('bad_request', `${what}: unknown tool`);
  }
  return obj as JsonObject;
}

function entryProfile(value: unknown, what: string): void {
  const obj = asObject(value, what);
  for (const key of Object.keys(obj)) {
    if (!(PROFILE_KEYS as string[]).includes(key)) fail('bad_request', `${what} has an unknown key`);
    const field = asObject(obj[key], `${what}.${key}`);
    exactKeys(field, ['value', 'origin'], `${what}.${key}`);
    parseProfileValue(key as ProfileKey, field['value'], `${what}.${key}.value`);
    asEnum(field['origin'], ENTRY_ORIGINS, `${what}.${key}.origin`);
  }
}

function entries(value: unknown, what: string): void {
  asArray(value, what, MAX_RESULT_ITEMS).forEach((e, i) => {
    const entry = asObject(e, `${what}[${i}]`);
    exactKeys(entry, ['name', 'profile', 'updated_at'], `${what}[${i}]`);
    name(entry['name'], `${what}[${i}].name`);
    entryProfile(entry['profile'], `${what}[${i}].profile`);
    asInt(entry['updated_at'], `${what}[${i}].updated_at`);
  });
}

function status(obj: Obj, allowed: readonly string[], what: string): string {
  return asEnum(obj['status'], allowed, `${what}.status`);
}

/** Validate an `ok:true` `result` object for `tool`; returns it unchanged. */
export function parseToolResult(tool: RelayTool, value: unknown, what = 'result'): JsonObject {
  const obj = asObject(value, what);
  switch (tool) {
    case 'search':
      exactKeys(obj, ['items'], what);
      entries(obj['items'], `${what}.items`);
      break;
    case 'list':
      exactKeys(obj, ['items'], what, ['next_cursor']);
      entries(obj['items'], `${what}.items`);
      optional(obj, 'next_cursor', (v) => bytesString(v, `${what}.next_cursor`, 256, 1));
      break;
    case 'describe':
      exactKeys(obj, ['name', 'profile', 'sensitivity'], what, ['created_at', 'rotated_at', 'last_device_label']);
      name(obj['name'], `${what}.name`);
      entryProfile(obj['profile'], `${what}.profile`);
      asEnum(obj['sensitivity'], SENSITIVITIES, `${what}.sensitivity`);
      optional(obj, 'created_at', (v) => asInt(v, `${what}.created_at`));
      optional(obj, 'rotated_at', (v) => asInt(v, `${what}.rotated_at`));
      optional(obj, 'last_device_label', (v) => bytesString(v, `${what}.last_device_label`, 64));
      break;
    case 'set':
      if (status(obj, ['written', 'conflict'], what) === 'written') {
        exactKeys(obj, ['status', 'revision'], what);
        asInt(obj['revision'], `${what}.revision`, 1);
      } else exactKeys(obj, ['status'], what);
      break;
    case 'delete':
      exactKeys(obj, ['status'], what);
      status(obj, ['deleted', 'conflict', 'not_found'], what);
      break;
    case 'request':
      exactKeys(obj, ['status', 'request_id'], what);
      status(obj, ['pending', 'granted', 'denied'], what);
      bytesString(obj['request_id'], `${what}.request_id`, 64, 1);
      break;
    case 'run':
      exactKeys(obj, ['exit_code', 'stdout', 'stderr', 'truncated'], what);
      asInt(obj['exit_code'], `${what}.exit_code`);
      asWellFormed(asString(obj['stdout'], `${what}.stdout`, Number.MAX_SAFE_INTEGER), `${what}.stdout`);
      asWellFormed(asString(obj['stderr'], `${what}.stderr`, Number.MAX_SAFE_INTEGER), `${what}.stderr`);
      asBool(obj['truncated'], `${what}.truncated`);
      break;
    case 'request_input':
      exactKeys(obj, ['request_id', 'input_pub'], what);
      asId(obj['request_id'], `${what}.request_id`);
      asB64(obj['input_pub'], `${what}.input_pub`, 32);
      break;
    case 'input_deliver':
      exactKeys(obj, ['status', 'receipt'], what);
      status(obj, ['stored'], what);
      asPrintableAscii(obj['receipt'], `${what}.receipt`, 128, 1);
      break;
    default:
      fail('bad_request', `${what}: unknown tool`);
  }
  return obj as JsonObject;
}

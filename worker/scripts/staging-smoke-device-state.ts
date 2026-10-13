/**
 * Persistent device keys for the staging smoke.
 *
 * ak-web binds a device key to the first account that mints a token with it and
 * caps live device keys per account, so the smoke must not bind fresh devices on
 * every run. Its device secrets live in a local state file (mode 0600, directory
 * 0700, outside the repository) and are reused across runs. The file also records
 * the account the keys were bound to, so another account's session is refused
 * before any request instead of failing at ak-web with `device_conflict`.
 *
 *   {"v":1,"account":"<ak-web user id>","devices":{"<label>":{"sign_seed":b64,"kx_secret":b64}}}
 *
 * Synthetic smoke keys only; never put a real device's keys here.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { b64decodeLength, b64encode, randomBytes, randomId } from '@ak-vault/protocol';
import { assertPrivateFile, fail } from './staging-smoke-ak-web-token.js';

export const DEFAULT_STATE_PATH = join(homedir(), '.ak-vault', 'staging-smoke-devices.json');

export interface DeviceSecrets {
  signSeed: Uint8Array;
  kxSecret: Uint8Array;
}

interface StateFile {
  v: 1;
  account: string;
  devices: Record<string, { sign_seed: string; kx_secret: string }>;
}

function parseState(text: string): StateFile | null {
  try {
    const value = JSON.parse(text) as Partial<StateFile>;
    if (value.v !== 1 || typeof value.account !== 'string' || typeof value.devices !== 'object' || value.devices === null) return null;
    for (const entry of Object.values(value.devices)) {
      b64decodeLength(entry.sign_seed, 32);
      b64decodeLength(entry.kx_secret, 32);
    }
    return value as StateFile;
  } catch {
    return null;
  }
}

function writeState(path: string, state: StateFile): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${randomId()}.tmp`;
  // `wx` refuses to follow or reuse an existing path; the rename is atomic.
  writeFileSync(tmp, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, path);
}

/**
 * Load the secrets for `labels`, creating and persisting any that are missing
 * before they are first used, so a device bound at ak-web is never lost.
 */
export function loadDeviceSecrets(path: string, account: string, labels: readonly string[]): Record<string, DeviceSecrets> {
  let state: StateFile = { v: 1, account, devices: {} };
  try {
    if (existsSync(path)) {
      assertPrivateFile(path, 'the smoke device state file');
      const parsed = parseState(readFileSync(path, 'utf8'));
      if (!parsed) fail('the smoke device state file is malformed (delete it to start over)');
      state = parsed;
    }
  } catch {
    fail('cannot read the smoke device state file');
  }
  if (state.account !== account) fail('the smoke device state file belongs to another account (set AK_STAGING_SMOKE_STATE_PATH)');

  const missing = labels.filter((label) => !state.devices[label]);
  if (missing.length > 0) {
    for (const label of missing) state.devices[label] = { sign_seed: b64encode(randomBytes(32)), kx_secret: b64encode(randomBytes(32)) };
    try {
      writeState(path, state);
    } catch {
      fail('cannot write the smoke device state file');
    }
  }
  return Object.fromEntries(
    labels.map((label) => {
      const entry = state.devices[label] as StateFile['devices'][string];
      return [label, { signSeed: b64decodeLength(entry.sign_seed, 32), kxSecret: b64decodeLength(entry.kx_secret, 32) }];
    }),
  );
}

/**
 * Route matrix for red-team tests: drive every vault read or write route as one
 * caller, and snapshot the server state a refused request must not move.
 */
import { appendAuditEntry, randomId, sha256b64, signCheckpoint, type JsonObject } from '@ak-vault/protocol';
import { call, type CallOptions, type CallResult, type TestDevice } from './api-client.js';
import { putTestBundle, sealTestBundle } from './recovery-bundle.js';
import type { VaultFixture } from './vault-fixture.js';

const v = { name: 'SYNTHETIC_TOKEN', value: 'synthetic-value' };

/** Collection read routes; tests add `/items/:iid` for an item they created. */
export const READ_ROUTES = ['/membership', '/wraps', '/changes', '/checkpoints', '/audit', '/recovery'];

/** Keys of `writeEverything` results, one per write route (item PUT three ways). */
export const WRITE_ROUTES = ['create', 'update', 'tombstone', 'checkpoint', 'audit', 'membership', 'recovery'];

/** Every read route of `fx`, plus one item read, as `device`. */
export async function readEverything(fx: VaultFixture, device: TestDevice, itemId: string, opts: CallOptions = {}): Promise<Record<string, CallResult>> {
  const out: Record<string, CallResult> = {};
  for (const sub of [...READ_ROUTES, `/items/${itemId}`]) out[sub] = await call(device, 'GET', `/v1/vaults/${fx.vaultId}${sub}`, undefined, opts);
  return out;
}

function checkpointBy(fx: VaultFixture, device: TestDevice) {
  return signCheckpoint(
    { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(new Uint8Array(1)), key_epoch: fx.keyEpoch, ts: Date.now(), author: device.keys.record.device_id },
    device.keys.signSecret,
  );
}

/** Every write route of `fx`, attempted by `device` with a well-formed body it signed. */
export async function writeEverything(fx: VaultFixture, device: TestDevice, itemId: string, opts: CallOptions = {}): Promise<Record<string, CallResult>> {
  const audit = appendAuditEntry({ vk: fx.vk.get(fx.keyEpoch)!, vaultId: fx.vaultId, keyEpoch: fx.keyEpoch, head: null, event: { op: 'item.reveal' } });
  const { event, wraps } = fx.enrollEvent(fx.newDevice(), [fx.keyEpoch], { id: device.keys.record.device_id, secret: device.keys.signSecret });
  return {
    create: await fx.write(device, randomId(), 0, v, opts),
    update: await fx.write(device, itemId, 1, v, opts),
    tombstone: await fx.write(device, itemId, 1, null, opts),
    checkpoint: await fx.post(device, '/checkpoints', checkpointBy(fx, device), opts),
    audit: await fx.post(device, '/audit', { start_seq: 0, prev: '', entries: [audit.entry as unknown as JsonObject] }, opts),
    membership: await call(device, 'POST', `/v1/vaults/${fx.vaultId}/membership`, { event: event as unknown as JsonObject, wraps: wraps as unknown as JsonObject[] }, opts),
    recovery: await putTestBundle(fx, device, sealTestBundle(fx, 1), fx.state.seq, opts),
  };
}

export const statuses = (results: Record<string, CallResult>) => Object.fromEntries(Object.entries(results).map(([k, r]) => [k, r.status]));
export const codes = (results: Record<string, CallResult>) => Object.fromEntries(Object.entries(results).map(([k, r]) => [k, r.json?.error?.code]));
export const every = <T>(keys: string[], value: T) => Object.fromEntries(keys.map((k) => [k, value]));

/** Server state, read by the owner, that a refused request must not move. */
export async function snapshot(fx: VaultFixture) {
  const changes = await fx.get(fx.owner, '/changes');
  const membership = await fx.get(fx.owner, '/membership');
  const checkpoints = await fx.get(fx.owner, '/checkpoints');
  const audit = await fx.get(fx.owner, '/audit');
  const recovery = await fx.get(fx.owner, '/recovery');
  return { head: changes.json.head, events: membership.json.events, checkpoints: checkpoints.json.checkpoints, audit: audit.json, recovery: [recovery.status, recovery.json] };
}

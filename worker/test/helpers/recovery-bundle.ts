/** Seals a real recovery bundle for a fixture vault (owner-signed checkpoint, current vault keys). */
import { generateRecoveryKey, randomBytes, sealRecoveryBundle, sha256b64, signCheckpoint, type RecoveryBundleWire } from '@ak-vault/protocol';
import { call, type CallOptions, type TestDevice } from './api-client.js';
import type { VaultFixture } from './vault-fixture.js';

export function sealTestBundle(fx: VaultFixture, seq: number, rk: Uint8Array = generateRecoveryKey(), recoverySignSk: Uint8Array = fx.recovery.secretKey): RecoveryBundleWire {
  const checkpoint = signCheckpoint(
    { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(randomBytes(4)), key_epoch: fx.keyEpoch, ts: Date.now(), author: fx.owner.keys.record.device_id },
    fx.owner.keys.signSecret,
  );
  const vk: Record<string, Uint8Array> = {};
  for (const [epoch, key] of fx.vk) vk[String(epoch)] = key;
  return sealRecoveryBundle({
    vaultId: fx.vaultId,
    bundleSeq: seq,
    vk,
    ownerSignPub: fx.owner.keys.record.sign_pub,
    recoverySignSk,
    checkpoint,
    password: 'synthetic test passphrase',
    rk,
    params: { t: 2, m: 19_456, p: 1 },
  });
}

/** `PUT /recovery` body: the bundle plus the membership position its sealer had verified (default: the fixture head). */
export function putTestBundle(fx: VaultFixture, device: TestDevice, bundle: unknown, membershipSeq: number = fx.state.seq, opts?: CallOptions) {
  return call(device, 'PUT', `/v1/vaults/${fx.vaultId}/recovery`, { bundle, membership_seq: membershipSeq } as never, opts);
}

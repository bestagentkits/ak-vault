/** Seals a real recovery bundle for a fixture vault (owner-signed checkpoint, current vault keys). */
import { generateRecoveryKey, randomBytes, sealRecoveryBundle, sha256b64, signCheckpoint, type RecoveryBundleWire } from '@ak-vault/protocol';
import type { VaultFixture } from './vault-fixture.js';

export function sealTestBundle(fx: VaultFixture, seq: number, rk: Uint8Array = generateRecoveryKey()): RecoveryBundleWire {
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
    recoverySignSk: fx.recovery.secretKey,
    checkpoint,
    password: 'synthetic test passphrase',
    rk,
    params: { t: 2, m: 19_456, p: 1 },
  });
}

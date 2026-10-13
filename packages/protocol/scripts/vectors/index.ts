/** Assemble every vector file: file name -> serialized JSON text. */
import { canonicalJsonVectors, kidVectors, aeadVectors } from './primitives.js';
import { itemVectors, passwordWrapVectors, recoveryWrapVectors, x25519WrapVectors } from './item-and-wraps.js';
import { membershipVectors } from './membership.js';
import { recordVectors } from './records.js';
import { auditVectors, checkpointVectors } from './checkpoints-audit.js';
import { policyVectors, proofVectors } from './policy-proof.js';
import { recoveryBundleVectors, rekeyWrapsVectors } from './bundle-rekey.js';
import { edgeCaseVectors } from './edge-cases.js';
import { deviceAddWrapsVectors } from './device-add-wraps.js';
import { removalFenceVectors } from './removal-fence.js';

const BUILDERS: Record<string, () => Record<string, unknown>> = {
  'canonical-json.json': canonicalJsonVectors,
  'kid.json': kidVectors,
  'aead.json': aeadVectors,
  'item.json': itemVectors,
  'wrap-x25519.json': x25519WrapVectors,
  'wrap-password.json': passwordWrapVectors,
  'wrap-recovery.json': recoveryWrapVectors,
  'membership.json': membershipVectors,
  'records.json': recordVectors,
  'checkpoints.json': checkpointVectors,
  'audit.json': auditVectors,
  'policy.json': policyVectors,
  'proof.json': proofVectors,
  'recovery-bundle.json': recoveryBundleVectors,
  'rekey-wraps.json': rekeyWrapsVectors,
  'device-add-wraps.json': deviceAddWrapsVectors,
  'removal-fence.json': removalFenceVectors,
  'edge-cases.json': edgeCaseVectors,
};

export const VECTOR_FILES = Object.keys(BUILDERS);

/** Build all vector files. Output is deterministic: identical on every run. */
export function buildAllVectors(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [file, build] of Object.entries(BUILDERS)) {
    const { version, description, ...rest } = build();
    out[file] = JSON.stringify({ version, description, ...rest }, null, 2) + '\n';
  }
  return out;
}

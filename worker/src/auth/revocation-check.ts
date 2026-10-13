/**
 * Live revocation lookup for every authenticated request (spec §9.3). Any error
 * reaching the registry fails closed with 503; a revoked session, device or
 * too-old token is 401 `unauthorized`.
 */
import type { Env } from '../env.js';
import { ApiError } from '../http/errors.js';
import type { VerifiedClaims } from './jwt-verify.js';

export const REVOCATION_REGISTRY_NAME = 'global';

export async function assertNotRevoked(env: Pick<Env, 'REVOCATIONS'>, claims: VerifiedClaims): Promise<void> {
  let revoked: boolean;
  try {
    const stub = env.REVOCATIONS.get(env.REVOCATIONS.idFromName(REVOCATION_REGISTRY_NAME));
    revoked = await stub.isRevoked({ sub: claims.sub, sid: claims.sid, did: claims.did, iat: claims.iat });
  } catch {
    throw new ApiError('unauthorized', { status: 503, message: 'revocation status unavailable', headers: { 'Retry-After': '5' } });
  }
  if (revoked !== false) throw new ApiError('unauthorized');
}

/**
 * Live revocation lookup for every authenticated request (spec §9.3). Any error
 * reaching the registry fails closed with 503; a revoked session, device or
 * too-old token is 401 `unauthorized`. MCP tokens carry no `did`, so only their
 * `sid` (= grant ID) and the account's minimum `iat` apply.
 */
import type { Env } from '../env.js';
import { ApiError } from '../http/errors.js';

export const REVOCATION_REGISTRY_NAME = 'global';

export interface RevocationSubject {
  sub: string;
  sid: string;
  iat: number;
  did?: string;
}

/** True when revoked; throws 503 `unauthorized` when the registry cannot answer. */
export async function isRevoked(env: Pick<Env, 'REVOCATIONS'>, subject: RevocationSubject): Promise<boolean> {
  let revoked: boolean;
  try {
    const stub = env.REVOCATIONS.get(env.REVOCATIONS.idFromName(REVOCATION_REGISTRY_NAME));
    revoked = await stub.isRevoked({ sub: subject.sub, sid: subject.sid, iat: subject.iat, ...(subject.did === undefined ? {} : { did: subject.did }) });
  } catch {
    throw new ApiError('unauthorized', { status: 503, message: 'revocation status unavailable', headers: { 'Retry-After': '5' } });
  }
  return revoked !== false;
}

export async function assertNotRevoked(env: Pick<Env, 'REVOCATIONS'>, subject: RevocationSubject): Promise<void> {
  if (await isRevoked(env, subject)) throw new ApiError('unauthorized');
}

/**
 * Live revocation lookup for every authenticated request (spec §9.3). Any error
 * reaching the registry fails closed with 503; a revoked session, device or
 * too-old token is 401 `unauthorized`.
 *
 * Device-bound sync tokens and MCP access tokens use separate checks so a device
 * token can never be checked without its `did`: MCP tokens carry no `did`, so only
 * their `sid` (= grant ID) and the account's minimum `iat` apply.
 */
import type { Env } from '../env.js';
import { ApiError } from '../http/errors.js';
import type { RevocationRegistry } from '../revocation/revocation-registry.js';
import type { VerifiedClaims } from './jwt-verify.js';

export const REVOCATION_REGISTRY_NAME = 'global';

/** The claims of a device-bound sync token that revocation applies to; `did` is required. */
export type DeviceRevocationSubject = Pick<VerifiedClaims, 'sub' | 'sid' | 'did' | 'iat'>;

/** The claims of an MCP access token that revocation applies to (`sid` = grant ID). */
export interface GrantRevocationSubject {
  sub: string;
  sid: string;
  iat: number;
}

type Registry = Pick<Env, 'REVOCATIONS'>;

async function ask(env: Registry, query: (stub: DurableObjectStub<RevocationRegistry>) => Promise<boolean>): Promise<boolean> {
  let revoked: boolean;
  try {
    revoked = await query(env.REVOCATIONS.get(env.REVOCATIONS.idFromName(REVOCATION_REGISTRY_NAME)));
  } catch {
    throw new ApiError('unauthorized', { status: 503, message: 'revocation status unavailable', headers: { 'Retry-After': '5' } });
  }
  return revoked !== false;
}

/** True when the device token's session, device or age is revoked; throws 503 when the registry cannot answer. */
export function isDeviceRevoked(env: Registry, s: DeviceRevocationSubject): Promise<boolean> {
  return ask(env, (stub) => stub.isRevoked({ sub: s.sub, sid: s.sid, did: s.did, iat: s.iat }));
}

export async function assertDeviceNotRevoked(env: Registry, s: DeviceRevocationSubject): Promise<void> {
  if (await isDeviceRevoked(env, s)) throw new ApiError('unauthorized');
}

/** True when the MCP grant (`sid`) or the token's age is revoked; throws 503 when the registry cannot answer. */
export function isGrantRevoked(env: Registry, s: GrantRevocationSubject): Promise<boolean> {
  return ask(env, (stub) => stub.isGrantRevoked({ sub: s.sub, sid: s.sid, iat: s.iat }));
}

export async function assertGrantNotRevoked(env: Registry, s: GrantRevocationSubject): Promise<void> {
  if (await isGrantRevoked(env, s)) throw new ApiError('unauthorized');
}

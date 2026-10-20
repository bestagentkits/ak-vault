/**
 * Remote MCP endpoint (spec §9.8): `POST /mcp` and the RFC 9728 protected-resource
 * metadata at `/.well-known/oauth-protected-resource` and
 * `/.well-known/oauth-protected-resource/mcp`. The Worker entry routes these paths
 * here only where remote access is enabled and adds the security headers.
 *
 * Not served yet: every path answers `404 not_found`. The endpoint verifies MCP
 * tokens with `verifyMcpToken`, checks revocation with `assertNotRevoked` (no
 * `did`), relays through `AccountRelay.dispatch` and seals with
 * `VaultDurableObject.enqueueSealed`.
 */
import type { Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { resultResponse } from '../http/responses.js';

export async function handleMcp(_request: Request, _env: Env): Promise<Response> {
  return resultResponse(errorResult(new ApiError('not_found')));
}

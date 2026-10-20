/**
 * Vault dashboard at `/app` and `/app/*` (ADR 0002 D1): static assets only, under
 * the dashboard CSP the Worker entry applies (`cspFor`). The entry routes these
 * paths here only where remote access is enabled.
 *
 * Not served yet: every path answers `404 not_found`.
 */
import type { Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { resultResponse } from '../http/responses.js';

export async function handleApp(_request: Request, _env: Env): Promise<Response> {
  return resultResponse(errorResult(new ApiError('not_found')));
}

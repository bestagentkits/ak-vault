/**
 * MCP protocol revisions served at `/mcp` (spec §9.8, ADR 0002 D6).
 *
 * - `2026-07-28` (modern): stateless, every request names its version in the
 *   `MCP-Protocol-Version` header and in `params._meta`, `server/discover`, the
 *   `Mcp-Method` / `Mcp-Name` headers mirror the body.
 * - `2025-11-25` (legacy): answered statelessly. `initialize` gets a result but no
 *   `Mcp-Session-Id` is ever issued, so every request stands alone. A request
 *   without the header is read as this revision (its own fallback rule).
 */
export const MODERN_VERSION = '2026-07-28';
export const LEGACY_VERSION = '2025-11-25';
export const SUPPORTED_VERSIONS = [MODERN_VERSION, LEGACY_VERSION] as const;
export type ProtocolVersion = (typeof SUPPORTED_VERSIONS)[number];

export const PROTOCOL_VERSION_HEADER = 'MCP-Protocol-Version';

/** `_meta` keys a modern request carries (2026-07-28 "Per-request protocol fields"). */
export const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';
export const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
export const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';

export type VersionResolution = { ok: true; version: ProtocolVersion } | { ok: false; requested: string };

/** The revision a request speaks, from its header; an unsupported value is refused by the caller. */
export function resolveVersion(header: string | null): VersionResolution {
  if (header === null) return { ok: true, version: LEGACY_VERSION };
  const value = header.trim();
  if ((SUPPORTED_VERSIONS as readonly string[]).includes(value)) return { ok: true, version: value as ProtocolVersion };
  // Echo only a bounded, printable form of what the client asked for.
  return { ok: false, requested: /^[\x20-\x7e]{1,32}$/.test(value) ? value : '' };
}

export function isModern(version: ProtocolVersion): boolean {
  return version === MODERN_VERSION;
}

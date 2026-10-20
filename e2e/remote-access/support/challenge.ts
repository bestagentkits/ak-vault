/** Parses a `WWW-Authenticate` Bearer challenge into its auth-params (RFC 9110 §11.2, RFC 6750 §3). */
export interface BearerChallenge {
  scheme: string;
  params: Record<string, string>;
  /** The raw parameter names in order, for exactness checks. */
  names: string[];
}

const PARAM = /([a-z_]+)="([^"\\]*)"/gi;

export function parseBearerChallenge(header: string | undefined): BearerChallenge | null {
  if (!header) return null;
  const space = header.indexOf(' ');
  const scheme = space === -1 ? header : header.slice(0, space);
  const rest = space === -1 ? '' : header.slice(space + 1);
  const params: Record<string, string> = {};
  const names: string[] = [];
  for (const match of rest.matchAll(PARAM)) {
    const [, name, value] = match;
    const key = name!.toLowerCase();
    if (params[key] !== undefined) return null;
    params[key] = value!;
    names.push(key);
  }
  // Anything besides the matched params and the `, ` separators is a syntax error.
  const leftover = rest.replace(PARAM, '').replace(/[\s,]/g, '');
  if (leftover.length > 0) return null;
  return { scheme, params, names };
}

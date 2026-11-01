/**
 * HTTP client of the platform log disclosure scan: a synthetic ES256 issuer the
 * lab Worker trusts (inline JWKS), and requests made the way a real client makes
 * them (device-bound token, AKV-Proof over method, URL and body, Idempotency-Key
 * on writes). Every credential it sends and every response it receives is handed
 * to the run's NeedleSet and response log, so the scan covers them; nothing here
 * prints a token, proof, key or body.
 */
import { b64encode, buildProof, createDeviceKeys, randomBytes, randomId, utf8Encode, type DeviceKeys, type DeviceKind, type Role } from '@ak-vault/protocol';
import { fetchRetrying } from './fetch-retrying.js';
import type { NeedleSet } from './needle-scan.js';

export interface LabDevice {
  label: string;
  keys: DeviceKeys;
  account: string;
  sid: string;
}

/** Synthetic token issuer. Its private key exists only in this process. */
export class LabIssuer {
  private constructor(
    readonly issuer: string,
    readonly audience: string,
    readonly kid: string,
    private readonly key: CryptoKey,
    readonly publicJwks: string,
  ) {}

  static async create(issuer: string, audience: string, needles: NeedleSet): Promise<LabIssuer> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
    if (!priv.d) throw new Error('issuer key export failed');
    needles.add('keys', priv.d);
    const kid = `logscan-${randomId()}`;
    const jwks = JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid, alg: 'ES256', use: 'sig' }] });
    return new LabIssuer(issuer, audience, kid, pair.privateKey, jwks);
  }

  /** The private key as a JWK, for a load-generator child process of the same run: process memory and IPC only, never disk or output. */
  async privateJwk(): Promise<JsonWebKey> {
    return crypto.subtle.exportKey('jwk', this.key);
  }

  /** The same issuer in another process of the run, from `privateJwk`; it can sign but has no JWKS to publish. */
  static async fromPrivateJwk(issuer: string, audience: string, kid: string, jwk: JsonWebKey): Promise<LabIssuer> {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return new LabIssuer(issuer, audience, kid, key, '');
  }

  /** Sign arbitrary header and claims (ES256, raw r||s). */
  async sign(header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
    const part = (v: unknown) => b64encode(utf8Encode(JSON.stringify(v)));
    const input = `${part(header)}.${part(claims)}`;
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.key, new Uint8Array(utf8Encode(input))));
    return `${input}.${b64encode(sig)}`;
  }

  mint(device: LabDevice, opts: { scope?: string; claims?: Record<string, unknown> } = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: this.issuer,
      aud: this.audience,
      sub: device.account,
      did: device.keys.record.device_id,
      sid: device.sid,
      jti: randomId(),
      scope: opts.scope ?? 'vault:read vault:write',
      iat: now,
      nbf: now,
      exp: now + 300,
      session_kind: 'email_otp', // mandatory claim (spec §9.1)
      ...opts.claims,
    };
    return this.sign({ alg: 'ES256', typ: 'at+jwt', kid: this.kid }, claims);
  }
}

export function labDevice(label: string, account: string, needles: NeedleSet, role: Role = 'owner', kind: DeviceKind = 'human'): LabDevice {
  const keys = createDeviceKeys({ account, role, kind });
  needles.add('keys', keys.signSecret, keys.kxSecret);
  return { label, keys, account, sid: `sid-${randomId()}` };
}

export interface CallOptions {
  /** Explicit bearer token; `null` sends none. Default: a fresh token for the device. */
  token?: string | null;
  scope?: string;
  /** Explicit proof header; `null` sends none. */
  proof?: string | null;
  /** Sign the proof with another key. */
  proofSecret?: Uint8Array;
  idempotencyKey?: string | null;
  rawBody?: Uint8Array;
  headers?: Record<string, string>;
}

export interface CallResult {
  status: number;
  // Wire JSON; callers check the fields they use.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
  token: string | null;
  proof: string | null;
}

export class LabClient {
  /** Status line, headers and body of every response, for the response-side scan. */
  readonly responses: string[] = [];
  requests = 0;

  constructor(
    readonly origin: string,
    readonly issuer: LabIssuer,
    private readonly needles: NeedleSet,
  ) {}

  /** Record a credential sent on the wire: whole, and each dot-separated segment that is long enough. */
  private credential(category: 'tokens' | 'proofs', value: string): void {
    this.needles.add(category, value, ...value.split('.').filter((p) => p.length >= 16));
  }

  async call(device: LabDevice | null, method: string, path: string, body?: unknown, opts: CallOptions = {}): Promise<CallResult> {
    const url = `${this.origin}${path}`;
    const bytes = opts.rawBody ?? (body === undefined ? new Uint8Array() : utf8Encode(JSON.stringify(body)));
    const headers: Record<string, string> = { ...opts.headers };
    let token: string | null = null;
    if (opts.token !== undefined) token = opts.token;
    else if (device) token = await this.issuer.mint(device, opts.scope ? { scope: opts.scope } : {});
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      this.credential('tokens', token);
    }
    let proof: string | null = null;
    if (opts.proof !== undefined) proof = opts.proof;
    else if (device && token) proof = buildProof({ htm: method, htu: url, ts: Date.now(), token, body: bytes, secretKey: opts.proofSecret ?? device.keys.signSecret });
    if (proof) {
      headers['AKV-Proof'] = proof;
      this.credential('proofs', proof);
    }
    const idem = opts.idempotencyKey === undefined ? (method === 'GET' ? null : `idem-${randomId()}`) : opts.idempotencyKey;
    if (idem) {
      headers['Idempotency-Key'] = idem;
      this.needles.add('idempotency_keys', idem);
    }
    if (bytes.length > 0) headers['Content-Type'] = 'application/json';
    return this.send(url, { method, headers, ...(method === 'GET' ? {} : { body: bytes }) }, token, proof);
  }

  /** A request outside the device auth path (webhook, public routes). */
  async raw(path: string, init: { method: string; headers?: Record<string, string>; body?: Uint8Array }): Promise<CallResult> {
    return this.send(`${this.origin}${path}`, init, null, null);
  }

  private async send(url: string, init: { method: string; headers?: Record<string, string>; body?: Uint8Array }, token: string | null, proof: string | null): Promise<CallResult> {
    this.requests++;
    const requestInit: RequestInit = { method: init.method, redirect: 'error' };
    if (init.headers) requestInit.headers = init.headers;
    if (init.body) requestInit.body = new Uint8Array(init.body);
    // Network failures are retried with the identical request: if an attempt did reach
    // the Worker, the repeat is refused as a replay and the step fails visibly.
    // The URL may carry a planted canary, so errors name only the method.
    const res = await fetchRetrying(url, () => requestInit, `${init.method} request to the lab Worker`);
    const text = await res.text();
    this.responses.push(`${res.status}\n${[...res.headers].map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${text}`);
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json, token, proof };
  }
}

/** HMAC-SHA256 over `ts\n body`, as ak-web signs the revocation webhook. */
export async function webhookSignature(secret: string, ts: string, body: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(utf8Encode(secret)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const message = new Uint8Array([...utf8Encode(`${ts}\n`), ...body]);
  return b64encode(new Uint8Array(await crypto.subtle.sign('HMAC', key, message)));
}

/** A random, URL- and header-safe canary with a recognisable prefix. */
export function canary(prefix: string): string {
  return `${prefix}-${b64encode(randomBytes(18))}`;
}

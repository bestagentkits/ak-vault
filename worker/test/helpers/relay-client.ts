/**
 * A test device holding `GET /v1/relay` open through the real Worker and relay
 * Durable Object: upgrade with token, device key and proof, then signed frames.
 */
import { env } from 'cloudflare:workers';
import { buildProof, cjson, signHello, signResult, type JsonObject, type RelayTool, type UnsignedResult } from '@ak-vault/protocol';
import worker from '../../src/index.js';
import type { Env } from '../../src/env.js';
import { BASE, type TestDevice } from './api-client.js';
import { mintToken } from './issuer.js';

export const RELAY_URL = `${BASE}/v1/relay`;
export const ALL_TOOLS: RelayTool[] = ['search', 'list', 'describe', 'set', 'delete', 'request', 'run'];

export interface UpgradeOptions {
  token?: string | null;
  scope?: string;
  sessionKind?: string;
  /** Extra or replacement token claims. */
  claims?: Record<string, unknown>;
  proof?: string | null;
  /** `AKV-Device-Key` value; default the device's sign_pub, `null` sends none. */
  deviceKey?: string | null;
  url?: string;
  method?: string;
  upgrade?: boolean;
  env?: Partial<Env>;
}

export function relayToken(device: TestDevice, opts: Pick<UpgradeOptions, 'scope' | 'sessionKind' | 'claims'> = {}): Promise<string> {
  return mintToken({
    sub: device.account,
    did: device.keys.record.device_id,
    sid: device.sid,
    ...(opts.scope ? { scope: opts.scope } : {}),
    claims: { ...(opts.sessionKind ? { session_kind: opts.sessionKind } : {}), ...opts.claims },
  });
}

export function relayProof(device: TestDevice, token: string, ts = Date.now()): string {
  return buildProof({ htm: 'GET', htu: RELAY_URL, ts, token, body: new Uint8Array(), secretKey: device.keys.signSecret });
}

/** Send the upgrade request; the raw Response (101 with `webSocket`, or a JSON error). */
export async function upgrade(device: TestDevice, opts: UpgradeOptions = {}): Promise<Response> {
  const token = opts.token === undefined ? await relayToken(device, opts) : opts.token;
  const headers: Record<string, string> = {};
  if (opts.upgrade !== false) headers['Upgrade'] = 'websocket';
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const proof = opts.proof === undefined ? (token ? relayProof(device, token) : null) : opts.proof;
  if (proof) headers['AKV-Proof'] = proof;
  const deviceKey = opts.deviceKey === undefined ? device.keys.record.sign_pub : opts.deviceKey;
  if (deviceKey) headers['AKV-Device-Key'] = deviceKey;
  return worker.fetch(new Request(opts.url ?? RELAY_URL, { method: opts.method ?? 'GET', headers }), { ...env, ...opts.env } as Env);
}

export interface Closed {
  code: number;
  reason: string;
}

/** One open relay connection with a queue of received frames. */
export class RelayConnection {
  private readonly frames: JsonObject[] = [];
  private waiters: (() => void)[] = [];
  closed: Closed | null = null;

  constructor(
    readonly device: TestDevice,
    readonly ws: WebSocket,
  ) {
    ws.addEventListener('message', (e) => {
      this.frames.push(JSON.parse(typeof e.data === 'string' ? e.data : '') as JsonObject);
      this.wake();
    });
    ws.addEventListener('close', (e) => {
      this.closed = { code: e.code, reason: e.reason };
      this.wake();
    });
  }

  private wake(): void {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  private async until<T>(check: () => T | undefined, what: string, timeoutMs = 5_000): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const value = check();
      if (value !== undefined) return value;
      const left = deadline - Date.now();
      if (left <= 0) throw new Error(`timed out waiting for ${what}`);
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, left);
        this.waiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }

  /** Next frame from the server (fails if the connection closes first). */
  next(timeoutMs?: number): Promise<JsonObject> {
    return this.until(
      () => {
        const f = this.frames.shift();
        if (f) return f;
        if (this.closed) throw new Error(`connection closed ${this.closed.code} while waiting for a frame`);
        return undefined;
      },
      'a frame',
      timeoutMs,
    );
  }

  /** Resolves with the close the server sent. */
  closedWith(timeoutMs?: number): Promise<Closed> {
    return this.until(() => this.closed ?? undefined, 'close', timeoutMs);
  }

  sendRaw(text: string): void {
    this.ws.send(text);
  }

  send(frame: JsonObject): void {
    this.ws.send(cjson(frame));
  }

  /** Send a signed `hello` and return the server's next frame (the `ready` on success). */
  async hello(vaults: string[], tools: RelayTool[] = ALL_TOOLS, opts: { ts?: number; deviceId?: string } = {}): Promise<JsonObject> {
    this.send(this.helloFrame(vaults, tools, opts));
    return this.next();
  }

  helloFrame(vaults: string[], tools: RelayTool[] = ALL_TOOLS, opts: { ts?: number; deviceId?: string } = {}): JsonObject {
    return signHello({ device_id: opts.deviceId ?? this.device.keys.record.device_id, vaults, tools, ts: opts.ts ?? Date.now() }, this.device.keys.signSecret) as unknown as JsonObject;
  }

  /** Answer a call with a signed result. */
  result(fields: UnsignedResult): void {
    this.send(signResult(fields, this.device.keys.signSecret) as unknown as JsonObject);
  }

  async reauth(token: string, proof?: string): Promise<void> {
    this.send({ v: 1, type: 'reauth', token, proof: proof ?? relayProof(this.device, token) });
  }

  close(): void {
    try {
      this.ws.close(1000, 'done');
    } catch {
      // already closed
    }
  }
}

/** Upgrade and accept; throws when the server refuses. */
export async function openRelay(device: TestDevice, opts: UpgradeOptions = {}): Promise<RelayConnection> {
  const res = await upgrade(device, opts);
  if (res.status !== 101 || !res.webSocket) throw new Error(`relay upgrade failed: ${res.status} ${await res.text()}`);
  res.webSocket.accept();
  return new RelayConnection(device, res.webSocket);
}

/** Open, say `hello` for `vaults` and wait for `ready`. */
export async function readyRelay(device: TestDevice, vaults: string[], tools: RelayTool[] = ALL_TOOLS, opts: UpgradeOptions = {}): Promise<RelayConnection> {
  const conn = await openRelay(device, opts);
  const ready = await conn.hello(vaults, tools);
  if (ready['type'] !== 'ready') throw new Error(`expected ready, got ${String(ready['type'])}`);
  return conn;
}

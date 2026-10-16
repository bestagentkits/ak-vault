/**
 * Synthetic workload of the cost measurement, in phases that each run alone in
 * their own whole minutes, so Cloudflare's per-minute analytics can be split by
 * operation: setup, no-op pull (the steady-state poll), push (item write), device
 * add, device remove (fence pull, removal and the rekey that follows it) and
 * revocation (webhook, then refused requests from the revoked devices).
 *
 * Every vault, device, token and value is synthetic and made by the protocol
 * library acting as a client (lab-client.ts, lab-vault-model.ts). Pulls, writes and
 * membership changes use separate vaults, so one phase's leftovers (for example
 * expired proof `jti` rows, deleted lazily by the next request in a vault) mostly
 * stay out of another phase; README.md lists what still carries over. Nothing here
 * prints a token, proof, key or body.
 */
import { randomId, utf8Encode } from '@ak-vault/protocol';
import { labDevice, webhookSignature, type CallResult, type LabClient, type LabDevice } from '../platform-log-scan/lab-client.js';
import { LabVault } from '../platform-log-scan/lab-vault-model.js';
import type { NeedleSet } from '../platform-log-scan/needle-scan.js';
import { sleep as sleepMs } from '../platform-log-scan/telemetry-polling.js';

/** Sleep that treats a deadline already passed as no wait. */
const sleep = (ms: number) => sleepMs(Math.max(0, ms));

export interface WorkloadShape {
  /** Two-device vaults that only poll. */
  pullVaults: number;
  pullSeconds: number;
  /** Interval between one device's polls. */
  pullIntervalMs: number;
  /** Two-device vaults whose owner writes; their second device is revoked at the end. */
  pushVaults: number;
  writesPerVault: number;
  /** Two-device vaults that add and then remove extra devices. */
  memberVaults: number;
  devicesPerMemberVault: number;
  /** Requests each revoked device makes after its revocation. */
  revokedRequests: number;
  /** Pace of sequential writes and membership changes in one vault. */
  stepIntervalMs: number;
}

/** About 1,100 requests over about 16 minutes. */
export const DEFAULT_SHAPE: WorkloadShape = {
  pullVaults: 6,
  pullSeconds: 300,
  pullIntervalMs: 5_000,
  pushVaults: 4,
  writesPerVault: 40,
  memberVaults: 4,
  devicesPerMemberVault: 4,
  revokedRequests: 10,
  stepIntervalMs: 1_000,
};

export type PhaseName = 'setup' | 'pull' | 'push' | 'device_add' | 'device_remove' | 'revocation';

export interface PhaseRecord {
  name: PhaseName;
  /** Wall clock at the first request and after the last response. */
  startedAt: number;
  endedAt: number;
  /** Operations of the phase's kind (pulls, writes, adds, removals, revoked devices). */
  operations: number;
  /** HTTP requests sent, by status. */
  statuses: Record<string, number>;
  requests: number;
  /** Requests whose status was not the expected one. */
  unexpected: number;
}

interface TwoDeviceVault {
  vault: LabVault;
  owner: LabDevice;
  laptop: LabDevice;
  items: { id: string; revision: number }[];
}

const SETUP_CONCURRENCY = 2;

/** Minimum idle time before a phase starts: the previous phase's last minute then has no traffic of the next. */
const IDLE_BETWEEN_PHASES_MS = 65_000;

/** Wait until at least `idleMs` after `since`, then to 2 s past the next whole minute. */
async function startOfOwnMinute(since: number, idleMs: number): Promise<void> {
  const earliest = Math.max(Date.now(), since + idleMs);
  const minute = Math.ceil(earliest / 60_000) * 60_000;
  await sleep(minute + 2_000 - Date.now());
}

class PhaseRun {
  readonly record: PhaseRecord;
  constructor(name: PhaseName) {
    this.record = { name, startedAt: Date.now(), endedAt: 0, operations: 0, statuses: {}, requests: 0, unexpected: 0 };
  }

  /** Count a response and check its status. */
  check(res: CallResult, ...expected: number[]): CallResult {
    const key = String(res.status);
    this.record.statuses[key] = (this.record.statuses[key] ?? 0) + 1;
    this.record.requests++;
    if (!expected.includes(res.status)) this.record.unexpected++;
    return res;
  }

  /** Like `check`, but a wrong status stops the run (later steps build on this one). */
  must(res: CallResult, what: string, ...expected: number[]): CallResult {
    this.check(res, ...expected);
    if (!expected.includes(res.status)) throw new Error(`${what} returned ${res.status} (${String(res.json?.error?.code ?? 'no error code')})`);
    return res;
  }

  done(): PhaseRecord {
    this.record.endedAt = Date.now();
    return this.record;
  }
}

/** Change-log head as a device sees it from an incremental pull at `cursor`. */
async function pullHead(phase: PhaseRun, v: LabVault, device: LabDevice, cursor: number): Promise<{ log_seq: number; log_head: string; changes: number }> {
  const res = phase.must(await v.call(device, 'GET', `/changes?cursor=${cursor}&limit=500`), 'pull', 200);
  const head = res.json?.head as { log_seq?: unknown; log_head?: unknown } | undefined;
  if (typeof head?.log_seq !== 'number' || typeof head.log_head !== 'string') throw new Error('pull response lacks the change-log head');
  return { log_seq: head.log_seq, log_head: head.log_head, changes: Array.isArray(res.json?.changes) ? (res.json.changes as unknown[]).length : -1 };
}

/** Genesis, enrol a second device (with its wrap), and write `items` items as the owner. */
async function createVault(phase: PhaseRun, client: LabClient, needles: NeedleSet, items: number): Promise<TwoDeviceVault> {
  const account = `acct-cost-${randomId()}`;
  const owner = labDevice('owner', account, needles);
  const laptop = labDevice('laptop', account, needles);
  const vault = new LabVault(client, needles, owner);
  phase.must(await vault.genesis(), 'genesis', 201);
  const enroll = vault.enrollEvent(laptop);
  phase.must(await vault.append(owner, enroll.event, enroll.wraps), 'device_add', 201);
  phase.must((await vault.receiveWrap(laptop, vault.state.seq)).res, 'wrap fetch', 200);
  const out: TwoDeviceVault = { vault, owner, laptop, items: [] };
  for (let i = 0; i < items; i++) {
    const id = randomId();
    phase.must(await vault.write(owner, id, 0, { name: `COST_SYNTHETIC_${i}`, value: randomId() }), 'item write', 200, 201);
    out.items.push({ id, revision: 1 });
  }
  return out;
}

export interface WorkloadResult {
  phases: PhaseRecord[];
  vaults: number;
  requests: number;
}

/**
 * Run every phase against `client`'s Worker. `webhookSecret` is the Worker's
 * revocation webhook secret (a lab secret: revocations are permanent).
 */
export async function runCostWorkload(client: LabClient, needles: NeedleSet, webhookSecret: string, shape: WorkloadShape, say: (line: string) => void): Promise<WorkloadResult> {
  const phases: PhaseRecord[] = [];
  const run = async (name: PhaseName, body: (phase: PhaseRun) => Promise<void>): Promise<void> => {
    await startOfOwnMinute(phases.at(-1)?.endedAt ?? 0, phases.length === 0 ? 0 : IDLE_BETWEEN_PHASES_MS);
    const phase = new PhaseRun(name);
    say(`phase ${name}: started`);
    try {
      await body(phase);
    } finally {
      const rec = phase.done();
      phases.push(rec);
      say(`phase ${name}: ${rec.operations} operation(s), ${rec.requests} request(s), statuses ${JSON.stringify(rec.statuses)}, ${rec.unexpected} unexpected, ${Math.round((rec.endedAt - rec.startedAt) / 1000)} s`);
    }
  };

  const pullVaults: TwoDeviceVault[] = [];
  const pushVaults: TwoDeviceVault[] = [];
  const memberVaults: TwoDeviceVault[] = [];
  const cursors = new Map<LabDevice, number>();
  await run('setup', async (phase) => {
    // A few vaults at a time: many parallel first requests on a fresh workers.dev host made the operator
    // network time out, and the identical retry is then refused as a proof replay.
    const make = async (n: number, items: number) => {
      const out: TwoDeviceVault[] = [];
      for (let i = 0; i < n; i += SETUP_CONCURRENCY) out.push(...(await Promise.all(Array.from({ length: Math.min(SETUP_CONCURRENCY, n - i) }, () => createVault(phase, client, needles, items)))));
      return out;
    };
    pullVaults.push(...(await make(shape.pullVaults, 3)));
    pushVaults.push(...(await make(shape.pushVaults, 3)));
    memberVaults.push(...(await make(shape.memberVaults, 3)));
    for (const t of pullVaults) for (const d of [t.owner, t.laptop]) cursors.set(d, (await pullHead(phase, t.vault, d, 0)).log_seq);
    for (const t of memberVaults) cursors.set(t.owner, (await pullHead(phase, t.vault, t.owner, 0)).log_seq);
    phase.record.operations = pullVaults.length + pushVaults.length + memberVaults.length;
  });

  await run('pull', (phase) => pullPhase(phase, pullVaults, cursors, shape));

  await run('push', async (phase) => {
    await Promise.all(
      pushVaults.map(async (t) => {
        for (let j = 0; j < shape.writesPerVault; j++) {
          const next = Date.now() + shape.stepIntervalMs;
          const item = t.items[j % t.items.length]!;
          phase.must(await t.vault.write(t.owner, item.id, item.revision, { name: `COST_SYNTHETIC_${j}`, value: randomId() }), 'item write', 200, 201);
          item.revision++;
          phase.record.operations++;
          await sleep(next - Date.now());
        }
      }),
    );
  });

  const added = new Map<TwoDeviceVault, LabDevice[]>();
  await run('device_add', async (phase) => {
    await Promise.all(
      memberVaults.map(async (t) => {
        const list: LabDevice[] = [];
        added.set(t, list);
        for (let j = 0; j < shape.devicesPerMemberVault; j++) {
          const next = Date.now() + shape.stepIntervalMs;
          const device = labDevice(`extra-${j}`, t.owner.account, needles);
          const enroll = t.vault.enrollEvent(device);
          phase.must(await t.vault.append(t.owner, enroll.event, enroll.wraps), 'device_add', 201);
          phase.must((await t.vault.receiveWrap(device, t.vault.state.seq)).res, 'wrap fetch', 200);
          list.push(device);
          phase.record.operations++;
          await sleep(next - Date.now());
        }
      }),
    );
  });

  await run('device_remove', async (phase) => {
    await Promise.all(
      memberVaults.map(async (t) => {
        let cursor = cursors.get(t.owner) ?? 0;
        for (const device of added.get(t) ?? []) {
          const next = Date.now() + shape.stepIntervalMs;
          // The owner's incremental pull gives the fence; then the removal and the rekey a removal requires.
          const head = await pullHead(phase, t.vault, t.owner, cursor);
          cursor = head.log_seq;
          const removal = t.vault.buildEvent('device_remove', { device_id: device.keys.record.device_id, reason: 'lost', log_fence: head.log_seq, log_head: head.log_head });
          phase.must(await t.vault.append(t.owner, removal), 'device_remove', 201);
          phase.must(await t.vault.rekey(t.owner), 'rekey', 201);
          phase.record.operations++;
          await sleep(next - Date.now());
        }
      }),
    );
  });

  await run('revocation', async (phase) => {
    for (const t of pushVaults) {
      const body = utf8Encode(JSON.stringify({ v: 1, event_id: randomId(), revoke_sids: [], revoke_dids: [t.laptop.keys.record.device_id], min_iat: [] }));
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = await webhookSignature(webhookSecret, ts, body);
      phase.must(await client.raw('/internal/v1/revocations', { method: 'POST', body, headers: { 'Content-Type': 'application/json', 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': sig } }), 'revocation webhook', 200);
      phase.record.operations++;
    }
    await Promise.all(
      pushVaults.map(async (t) => {
        for (let j = 0; j < shape.revokedRequests; j++) {
          const next = Date.now() + shape.stepIntervalMs;
          phase.check(await t.vault.call(t.laptop, 'GET', '/changes?cursor=0'), 401);
          await sleep(next - Date.now());
        }
      }),
    );
  });

  return { phases, vaults: pullVaults.length + pushVaults.length + memberVaults.length, requests: phases.reduce((n, p) => n + p.requests, 0) };
}

/** No-op polls by both devices of each vault, from the head each saw in setup. */
async function pullPhase(phase: PhaseRun, vaults: TwoDeviceVault[], cursors: Map<LabDevice, number>, shape: WorkloadShape): Promise<void> {
  const pollers = vaults.flatMap((t) => [t.owner, t.laptop].map((device) => ({ v: t.vault, device, cursor: cursors.get(device) ?? 0 })));
  const deadline = phase.record.startedAt + shape.pullSeconds * 1000;
  await Promise.all(
    pollers.map(async (p, i) => {
      const offset = (shape.pullIntervalMs * i) / pollers.length;
      await sleep(offset);
      for (let k = 1; Date.now() < deadline; k++) {
        // Counted, not fatal: one lost poll (for example a network retry refused as a replay) does not end the series.
        const res = phase.check(await p.v.call(p.device, 'GET', `/changes?cursor=${p.cursor}`), 200);
        if (res.status === 200 && (res.json?.changes as unknown[] | undefined)?.length !== 0) phase.record.unexpected++;
        phase.record.operations++;
        await sleep(phase.record.startedAt + offset + k * shape.pullIntervalMs - Date.now());
      }
    }),
  );
}

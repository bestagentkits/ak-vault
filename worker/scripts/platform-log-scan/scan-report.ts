/**
 * Result of the platform log disclosure scan: which categories gate the run, the
 * per-source hit table printed to stdout, and the optional JSON report. Both hold
 * counts only, never a planted value, credential or captured telemetry.
 */
import { writeFileSync } from 'node:fs';

/** Categories that must have zero hits everywhere. The others are reported for context. */
export const GATING = ['secret_names', 'secret_values', 'recovery_material', 'tokens', 'proofs', 'keys', 'idempotency_keys', 'webhook_material', 'request_body_canaries', 'request_header_canaries'];
/** Request URLs (with their opaque IDs, and any canary a client puts there) are platform request metadata; lab_harness is the lab's own dump secret. */
export const INFORMATIONAL = ['url_canaries', 'opaque_ids', 'lab_harness'];

export const say = (line: string) => process.stdout.write(`${line}\n`);

export interface SourceResult {
  bytes: number;
  rows?: number;
  hits: Record<string, number>;
}

export interface ScanOutcome {
  commit: string;
  dirty: boolean;
  lab: string;
  observability: { production: unknown; scanned: unknown };
  needleForms: Record<string, number>;
  steps: { total: number; unexpected: number };
  trafficRequests: number;
  tailFetchEvents: number;
  analyticsRequests: number;
  sources: Record<string, SourceResult>;
  cleanup: { scriptGone: boolean; namespacesLeft: number };
  problems: string[];
  cleanupProblems: string[];
}

/** Print the hit table and verdict, write the report if asked; true when the run passes. */
export function concludeScan(outcome: ScanOutcome, reportPath: string | undefined): boolean {
  const seeded = Object.keys(outcome.needleForms);
  const problems = [...outcome.problems];
  for (const c of GATING) if (!seeded.includes(c)) problems.push(`category ${c} was never seeded`);
  const categories = [...GATING.filter((c) => seeded.includes(c)), ...seeded.filter((c) => !GATING.includes(c))];
  say('\nhits per source (gating categories first):');
  say(['source', 'bytes', 'rows', ...categories].join('\t'));
  for (const [source, r] of Object.entries(outcome.sources)) say([source, r.bytes, r.rows ?? '', ...categories.map((c) => r.hits[c] ?? 0)].join('\t'));
  const gatingHits = Object.values(outcome.sources).reduce((n, r) => n + GATING.reduce((m, c) => m + (r.hits[c] ?? 0), 0), 0);
  const ok = gatingHits === 0 && problems.length === 0 && outcome.cleanupProblems.length === 0;
  for (const p of problems) say(`problem: ${p}`);
  say(`tail captured ${outcome.tailFetchEvents} fetch invocation(s) for ${outcome.trafficRequests} traffic request(s) plus warm-up probes; analytics counted ${outcome.analyticsRequests}`);
  say(`\nresult: ${ok ? 'PASS' : 'FAIL'} (${gatingHits} gating hit(s))`);
  if (reportPath) {
    const report = {
      date: new Date().toISOString(),
      commit: outcome.commit,
      dirty: outcome.dirty,
      lab: outcome.lab,
      observability: outcome.observability,
      gating: GATING,
      informational: INFORMATIONAL,
      needle_forms: outcome.needleForms,
      steps: outcome.steps,
      traffic_requests: outcome.trafficRequests,
      tail_fetch_events: outcome.tailFetchEvents,
      analytics_requests: outcome.analyticsRequests,
      sources: outcome.sources,
      cleanup: outcome.cleanup,
      problems: [...problems, ...outcome.cleanupProblems],
      result: ok ? 'pass' : 'fail',
    };
    writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  }
  return ok;
}

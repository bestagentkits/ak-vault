/**
 * Command-line options of the platform log disclosure scan. The lab name must be
 * in the lab namespace, and the report and raw captures (which hold the run's
 * synthetic credentials and canaries) must be written outside the repository.
 */
import { existsSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { LAB_NAME_PATTERN, WORKER_DIR } from './lab-worker-lifecycle.js';

export interface ScanOptions {
  name: string;
  report?: string;
  keepCapture?: string;
}

/** Captures and reports hold synthetic credentials and canaries: never let them land in the repository. */
function outsideRepository(path: string, flag: string): string {
  const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim();
  const abs = resolve(path);
  for (const root of new Set([top, realpathSync(top)])) {
    const rel = relative(root, abs);
    if (rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))) throw new Error(`${flag} must be outside the repository`);
  }
  return abs;
}

/** Parse `--name`, `--report` and `--keep-capture`; refuses lab names outside the lab namespace and output inside the repository. */
export function scanOptions(rawArgv: string[]): ScanOptions {
  // `pnpm scan:platform-logs -- …` forwards the separator itself.
  const argv = rawArgv[0] === '--' ? rawArgv.slice(1) : rawArgv;
  const stamp = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Saigon', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    .format(new Date())
    .replace(/[^0-9]/g, '');
  let name = `ak-vault-lab-logscan-${stamp}`;
  let report: string | undefined;
  let keepCapture: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--name') name = argv[++i] ?? '';
    else if (argv[i] === '--report') report = outsideRepository(argv[++i] ?? '', '--report');
    else if (argv[i] === '--keep-capture') keepCapture = outsideRepository(argv[++i] ?? '', '--keep-capture');
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (!LAB_NAME_PATTERN.test(name)) throw new Error(`lab name must match ${LAB_NAME_PATTERN}`);
  if (keepCapture !== undefined && existsSync(keepCapture)) throw new Error('--keep-capture needs a directory that does not exist yet');
  return { name, ...(report ? { report } : {}), ...(keepCapture ? { keepCapture } : {}) };
}

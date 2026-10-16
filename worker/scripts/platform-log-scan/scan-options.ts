/**
 * Command-line options of the platform log disclosure scan. The lab name must be
 * in the lab namespace, and the report and raw captures (which hold the run's
 * synthetic credentials and canaries) must be written outside the repository.
 */
import { existsSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { LAB_NAME_PATTERN, WORKER_DIR } from './lab-worker-lifecycle.js';

export interface ScanOptions {
  name: string;
  report?: string;
  keepCapture?: string;
}

/** The real path of `path`, resolving symlinks through its nearest existing ancestor. */
function realPathOf(path: string): string {
  const abs = resolve(path);
  if (existsSync(abs)) return realpathSync(abs);
  const parent = dirname(abs);
  return parent === abs ? abs : join(realPathOf(parent), basename(abs));
}

/** True when `path` is `root` or inside it (case-insensitively on macOS, whose default volumes are). */
function within(root: string, path: string): boolean {
  const fold = (p: string) => (process.platform === 'darwin' ? p.toLowerCase() : p);
  const rel = relative(fold(root), fold(path));
  return rel === '' || !(rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel));
}

/** Captures and reports hold synthetic credentials and canaries: never let them land in this repository or any of its worktrees. */
export function outsideRepository(path: string, flag: string): string {
  const target = realPathOf(path);
  const worktrees = execFileSync('git', ['worktree', 'list', '--porcelain'], { cwd: WORKER_DIR, encoding: 'utf8' })
    .split('\n')
    .filter((line) => line.startsWith('worktree '))
    .map((line) => realPathOf(line.slice('worktree '.length)));
  if (worktrees.length === 0) throw new Error('could not list the repository worktrees');
  if (worktrees.some((root) => within(root, target))) throw new Error(`${flag} must be outside the repository`);
  return target;
}

/** Current time in Asia/Saigon as digits (yyyymmddhhmmss), for default lab names. */
export function saigonStamp(): string {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Saigon', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    .format(new Date())
    .replace(/[^0-9]/g, '');
}

/** Parse `--name`, `--report` and `--keep-capture`; refuses lab names outside the lab namespace and output inside the repository. */
export function scanOptions(rawArgv: string[]): ScanOptions {
  // `pnpm scan:platform-logs -- …` forwards the separator itself.
  const argv = rawArgv[0] === '--' ? rawArgv.slice(1) : rawArgv;
  let name = `ak-vault-lab-logscan-${saigonStamp()}`;
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

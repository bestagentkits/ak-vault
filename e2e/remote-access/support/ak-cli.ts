/**
 * Drives a relay-capable `ak` binary (AK_BIN, the phase-10 build) inside an owner
 * HOME that the operator prepared as a temporary directory (AK_E2E_OWNER_HOME). The
 * suite refuses the operator's real home directory, so the user's own `ak` state is
 * never read or written. Output is matched in memory for the codes and digits a step
 * needs and is never printed or attached to the report.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

export interface AkHome {
  dir: string;
  env: Record<string, string>;
}

/** The owner HOME for `ak`. Throws if it is unset or is the operator's real home. */
export function akHomeFromEnv(raw: string | undefined): AkHome {
  if (!raw) throw new Error('AK_E2E_OWNER_HOME is unset');
  const dir = resolve(raw);
  if (dir.toLowerCase() === resolve(homedir()).toLowerCase()) throw new Error('AK_E2E_OWNER_HOME must not be the operator home directory');
  const env: Record<string, string> = {
    HOME: dir,
    USERPROFILE: dir,
    APPDATA: resolve(dir, 'AppData', 'Roaming'),
    LOCALAPPDATA: resolve(dir, 'AppData', 'Local'),
    XDG_CONFIG_HOME: resolve(dir, '.config'),
    AK_NO_AUTO_UPDATE: '1',
    SystemRoot: process.env['SystemRoot'] ?? 'C:\\Windows',
    PATH: process.env['PATH'] ?? '',
  };
  return { dir, env };
}

export interface AkRun {
  /** Resolves with the first match of `pattern` in the output, or rejects on exit or timeout. */
  waitFor(pattern: RegExp, timeoutMs?: number): Promise<RegExpExecArray>;
  write(line: string): void;
  /** Writes `text` verbatim (no line end) and closes stdin. */
  end(text: string): void;
  exit(timeoutMs?: number): Promise<number | null>;
  kill(): void;
}

/** Starts `bin` with `args` in the given home. Output stays in memory. */
export function runAk(bin: string, args: string[], home: AkHome): AkRun {
  const child: ChildProcessWithoutNullStreams = spawn(bin, args, { env: home.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let buffer = '';
  let closed: number | null | undefined;
  const onData = (chunk: string): void => {
    buffer += chunk;
  };
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  child.once('exit', (code) => {
    closed = code;
  });

  return {
    waitFor(pattern, timeoutMs = 60_000) {
      return new Promise((resolve, reject) => {
        const deadline = Date.now() + timeoutMs;
        const poll = setInterval(() => {
          const match = pattern.exec(buffer);
          if (match) {
            clearInterval(poll);
            return resolve(match);
          }
          if (closed !== undefined || Date.now() > deadline) {
            clearInterval(poll);
            return reject(new Error(closed !== undefined ? `ak exited (${closed ?? 'signal'}) before the expected output` : 'ak output timeout'));
          }
        }, 250);
      });
    },
    write(line) {
      child.stdin.write(`${line}\n`);
    },
    end(text) {
      child.stdin.end(text);
    },
    exit(timeoutMs = 60_000) {
      if (closed !== undefined) return Promise.resolve(closed);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('ak exit timeout')), timeoutMs);
        child.once('exit', (code) => {
          clearTimeout(timer);
          resolve(code);
        });
      });
    },
    kill() {
      if (closed === undefined) child.kill('SIGTERM');
    },
  };
}

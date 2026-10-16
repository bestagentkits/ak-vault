#!/usr/bin/env node
// Disclosure scan of the vault's persisted state and logs.
//
// Reads needles (synthetic secret names, values, the vault password, the
// recovery key, token markers) one per line on stdin, then searches:
//   - the raw bytes of every file under each directory given (SQLite files,
//     their WAL and journal, wrangler's cache, the Worker log);
//   - a row dump of every table of every SQLite database found, with blob
//     cells also rendered as base64, as worker/test/helpers/disclosure-scan.ts
//     does for the vitest pool.
// Each needle is searched in every encoding that helper covers: UTF-8, hex,
// and base64/base64url at all three byte alignments.
//
// Output is JSON on stdout: counts and, for a hit, the file and needle
// index only. A needle is never printed. Exit 0 when nothing is found, 1 on
// a hit, 2 when the scan itself failed (fail closed).
//
// Usage: node disclosure-scan.mjs DIR... < needles

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const MIN_NEEDLE = 6;

function encodings(secret) {
  const bytes = Buffer.from(secret, 'utf8');
  const out = new Set([secret, bytes.toString('hex')]);
  for (let k = 0; k < 3; k++) {
    const shifted = Buffer.concat([Buffer.alloc(k), bytes]);
    const b64 = shifted.toString('base64');
    const core = b64.slice(Math.ceil((k * 8) / 6), Math.floor(((k + bytes.length) * 8) / 6));
    if (core.length >= 8) {
      out.add(core);
      out.add(core.replaceAll('+', '-').replaceAll('/', '_'));
    }
  }
  return [...out];
}

function walk(dir, files = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, files);
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

function readNeedles() {
  const text = readFileSync(0, 'utf8');
  const needles = [...new Set(text.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.length > 0))];
  const short = needles.filter((n) => n.length < MIN_NEEDLE);
  if (short.length) throw new Error(`${short.length} needle(s) shorter than ${MIN_NEEDLE} characters would match by chance`);
  if (needles.length === 0) throw new Error('no needles on stdin');
  return needles;
}

async function dumpSqlite(path) {
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
    const parts = [];
    for (const table of tables) {
      for (const row of db.prepare(`SELECT * FROM "${table.replaceAll('"', '""')}"`).all()) {
        for (const value of Object.values(row)) {
          if (value instanceof Uint8Array) parts.push(Buffer.from(value).toString('utf8'), Buffer.from(value).toString('base64'));
          else parts.push(String(value));
        }
      }
    }
    return { tables: tables.length, text: parts.join('\n') };
  } finally {
    db.close();
  }
}

async function main() {
  const dirs = process.argv.slice(2);
  if (dirs.length === 0) throw new Error('usage: disclosure-scan.mjs DIR... < needles');
  const needles = readNeedles();
  const forms = needles.map((n) => encodings(n));
  const report = { files: 0, bytes: 0, sqlite_databases: 0, sqlite_tables: 0, encodings: 0, hits: [] };
  report.encodings = forms.reduce((n, f) => n + f.length, 0);

  const check = (label, haystack) => {
    forms.forEach((set, index) => {
      if (set.some((form) => haystack.includes(form))) report.hits.push({ where: label, needle_index: index });
    });
  };

  for (const dir of dirs) {
    if (!statSync(dir).isDirectory()) throw new Error(`not a directory: ${dir}`);
    for (const file of walk(dir)) {
      const bytes = readFileSync(file);
      report.files += 1;
      report.bytes += bytes.length;
      // latin1 keeps every byte, so both text and binary pages are searched.
      check(file, bytes.toString('latin1'));
      if (bytes.subarray(0, 16).toString('latin1') === 'SQLite format 3\u0000') {
        const dump = await dumpSqlite(file);
        report.sqlite_databases += 1;
        report.sqlite_tables += dump.tables;
        check(`${file} (table dump)`, dump.text);
      }
    }
  }
  if (report.files === 0) throw new Error('nothing to scan: no files under the given directories');
  if (report.sqlite_databases === 0) throw new Error('no SQLite database found: the Durable Object state is missing');
  report.needles = needles.length;
  report.ok = report.hits.length === 0;
  process.stdout.write(`${JSON.stringify(report)}\n`);
  return report.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stdout.write(`${JSON.stringify({ ok: false, error: String(err && err.message ? err.message : err) })}\n`);
    process.exit(2);
  },
);

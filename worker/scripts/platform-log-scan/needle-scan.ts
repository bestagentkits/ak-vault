/**
 * Needle search for the platform log disclosure scan. A needle is a synthetic
 * secret planted by the run; it is searched in every encoding a careless code
 * path or platform pipeline might emit: UTF-8, hex, and base64/base64url at all
 * three byte alignments (the same forms as worker/test/helpers/disclosure-scan.ts
 * and e2e/docker/scanner/disclosure-scan.mjs, which run in other runtimes).
 *
 * Results are counts per category and source only. Needle values never leave
 * this module: nothing here prints, logs or returns them.
 */

/** Needles shorter than this would match random text by chance. */
export const MIN_NEEDLE_LENGTH = 12;

export type Needle = string | Uint8Array;

export class NeedleSet {
  private readonly byCategory = new Map<string, Set<string>>();

  /** Add needles (strings are searched as text too; bytes only in their encodings). */
  add(category: string, ...needles: Needle[]): void {
    let set = this.byCategory.get(category);
    if (!set) this.byCategory.set(category, (set = new Set()));
    for (const needle of needles) for (const form of encodings(needle)) set.add(form);
  }

  categories(): string[] {
    return [...this.byCategory.keys()];
  }

  /** Number of distinct encoded forms per category (evidence that every category was seeded). */
  formCounts(): Record<string, number> {
    return Object.fromEntries([...this.byCategory].map(([c, set]) => [c, set.size]));
  }

  /** Occurrences of every form of every needle in `haystack`, per category. */
  count(haystack: string): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [category, forms] of this.byCategory) {
      let hits = 0;
      for (const form of forms) hits += occurrences(haystack, form);
      out[category] = hits;
    }
    return out;
  }
}

function occurrences(haystack: string, needle: string): number {
  let n = 0;
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + needle.length)) n++;
  return n;
}

/** Every form in which `needle` could appear inside a larger text or encoded buffer. */
export function encodings(needle: Needle): string[] {
  const bytes = typeof needle === 'string' ? new TextEncoder().encode(needle) : needle;
  const out = new Set<string>();
  if (typeof needle === 'string') out.add(needle);
  out.add(Buffer.from(bytes).toString('hex'));
  for (let k = 0; k < 3; k++) {
    const shifted = Buffer.concat([Buffer.alloc(k), Buffer.from(bytes)]);
    const b64 = shifted.toString('base64');
    // Keep only the characters fully determined by the needle's bits.
    const core = b64.slice(Math.ceil((k * 8) / 6), Math.floor(((k + bytes.length) * 8) / 6));
    if (core.length >= MIN_NEEDLE_LENGTH) {
      out.add(core);
      out.add(core.replaceAll('+', '-').replaceAll('/', '_'));
    }
  }
  for (const form of out) if (form.length < MIN_NEEDLE_LENGTH) throw new Error(`a needle form is shorter than ${MIN_NEEDLE_LENGTH} characters`);
  return [...out];
}

/** Positive control: a needle embedded at any byte alignment inside base64 is found. */
export function selfTestNeedleScan(): void {
  const secret = crypto.getRandomValues(new Uint8Array(24));
  for (let k = 0; k < 3; k++) {
    const buf = Buffer.concat([Buffer.alloc(k, 7), Buffer.from(secret), Buffer.alloc(2, 9)]);
    const set = new NeedleSet();
    set.add('probe', secret);
    if ((set.count(`x ${buf.toString('base64url')} y`)['probe'] ?? 0) === 0) throw new Error('scanner self-test failed');
  }
  if (!encodings('abcdefabcdef').includes('616263646566616263646566')) throw new Error('scanner self-test failed');
}

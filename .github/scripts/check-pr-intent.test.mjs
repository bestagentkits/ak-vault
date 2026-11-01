import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { checkIntent } from './check-pr-intent.mjs';

const filled = (overrides = {}, nl = '\n') => {
  const fields = {
    goal: 'Close #1: do the thing.',
    touches_contracts: 'none',
    invariants_assumed: 'the spec is unchanged',
    supersedes: 'none',
    risk_class: 'low',
    ...overrides,
  };
  const lines = Object.entries(fields).filter(([, v]) => v !== undefined).map(([k, v]) => `- ${k}: ${v}`);
  return ['Closes #1', '', '## Intent', '', ...lines, '', '## Change', 'text'].join(nl);
};

test('a complete block passes, with LF and CRLF line endings', () => {
  assert.deepEqual(checkIntent(filled()), []);
  assert.deepEqual(checkIntent(filled({}, '\r\n')), []);
});

test('the block may be the last section of the body', () => {
  assert.deepEqual(checkIntent(filled().split('\n## Change')[0]), []);
});

test('a missing section or an empty body fails', () => {
  assert.deepEqual(checkIntent('Closes #1\n\n## Change\ntext'), ['no `## Intent` section']);
  assert.deepEqual(checkIntent(undefined), ['no `## Intent` section']);
});

test('the unfilled template fails on every field', () => {
  const template = readFileSync(new URL('../pull_request_template.md', import.meta.url), 'utf8');
  assert.equal(checkIntent(template).length, 5);
});

test('a section inside an HTML comment does not count', () => {
  assert.deepEqual(checkIntent(`<!--\n${filled()}\n-->`), ['no `## Intent` section']);
});

test('missing, empty and placeholder fields fail', () => {
  assert.deepEqual(checkIntent(filled({ supersedes: undefined })), ['`supersedes` is missing']);
  assert.deepEqual(checkIntent(filled({ goal: '' })), ['`goal` is empty']);
  assert.deepEqual(checkIntent(filled({ goal: 'TBD' })), ['`goal` is a placeholder (`TBD`)']);
  assert.deepEqual(checkIntent(filled({ goal: 'TBD.' })), ['`goal` is a placeholder (`TBD.`)']);
  assert.deepEqual(checkIntent(filled({ goal: '…' })), ['`goal` is a placeholder (`…`)']);
});

test('a heading that only starts with Intent is not the section', () => {
  assert.deepEqual(checkIntent(filled().replace('## Intent', '## Intentional')), ['no `## Intent` section']);
});

test('a nested ### heading does not end the section', () => {
  assert.deepEqual(checkIntent(filled().replace('- supersedes:', '### Notes\n\n- supersedes:')), []);
});

test('the first copy of a duplicated field is the one checked', () => {
  const body = filled().replace('- goal: Close #1: do the thing.', '- goal:\n- goal: Close #1: do the thing.');
  assert.deepEqual(checkIntent(body), ['`goal` is empty']);
});

test('a field outside the Intent section does not count', () => {
  const body = filled({ goal: undefined }) + '\n- goal: written under Change';
  assert.deepEqual(checkIntent(body), ['`goal` is missing']);
});

test('risk_class must be one of the listed classes', () => {
  assert.deepEqual(checkIntent(filled({ risk_class: 'security' })), []);
  assert.match(checkIntent(filled({ risk_class: 'medium' }))[0], /^`risk_class` `medium` is not one of/);
});

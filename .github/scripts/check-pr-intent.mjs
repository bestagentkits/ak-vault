// Refuses a pull request whose body has no complete `## Intent` block. The rules
// match parseIntent in the AgentKit train gate (bestagentkits/agentkit,
// tools/ci/train-intent-gate.mjs), so a block that passes here passes there.
// The body comes from the PR_BODY environment variable, never from the command
// line, so its contents are never interpreted by a shell.
import { pathToFileURL } from 'node:url';

export const INTENT_FIELDS = ['goal', 'touches_contracts', 'invariants_assumed', 'supersedes', 'risk_class'];
export const RISK_CLASSES = ['low', 'os_risk', 'release-pipeline', 'security', 'data-migration'];
// Template leftovers that are not an answer. `none` stays valid: the template asks for it.
const PLACEHOLDERS = new Set(['tbd', 'todo', '?', '...', '…']);
const isPlaceholder = (value) => {
  const bare = value.toLowerCase();
  return PLACEHOLDERS.has(bare) || PLACEHOLDERS.has(bare.replace(/[.:;!]+$/, ''));
};

export function checkIntent(body) {
  const text = String(body ?? '').replace(/<!--[\s\S]*?-->/g, '');
  const section = /^## +Intent\s*$([\s\S]*?)(?=^## |(?![\s\S]))/m.exec(text);
  if (!section) return ['no `## Intent` section'];
  const problems = [];
  for (const field of INTENT_FIELDS) {
    const match = new RegExp(`^\\s*[-*]\\s*${field}\\s*:(.*)$`, 'm').exec(section[1]);
    const value = match ? match[1].trim() : '';
    if (!match) problems.push(`\`${field}\` is missing`);
    else if (!value) problems.push(`\`${field}\` is empty`);
    else if (isPlaceholder(value)) problems.push(`\`${field}\` is a placeholder (\`${value}\`)`);
    else if (field === 'risk_class' && !RISK_CLASSES.includes(value)) {
      problems.push(`\`risk_class\` \`${value}\` is not one of ${RISK_CLASSES.join(', ')}`);
    }
  }
  return problems;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const problems = checkIntent(process.env.PR_BODY);
  if (problems.length > 0) {
    console.error('The PR description needs a complete `## Intent` block (see .github/pull_request_template.md):');
    for (const problem of problems) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log('Intent block complete.');
}

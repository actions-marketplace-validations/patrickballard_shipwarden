import { SEVERITIES } from './util.js';

export const MARKER = '<!-- shipwarden -->';
const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' };

export function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function summaryLine(findings) {
  const counts = countBySeverity(findings);
  return SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(' · ');
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const cell = (text) => text.replace(/\|/g, '\\|').replace(/\n/g, ' ');

/**
 * @param {{findings: object[], filesScanned: number, stack: string[]}} result
 * @param {{link?: (file: string, line: number) => string, scopeNote?: string, aiNote?: string, maxItems?: number}} opts
 */
export function toMarkdown(result, { link, scopeNote, aiNote, maxItems = 30 } = {}) {
  const { findings } = result;
  const scanned = `Scanned ${plural(result.filesScanned, 'file')}${scopeNote ? ` · reporting on ${scopeNote}` : ''}${result.stack.length ? ` · ${result.stack.join(', ')}` : ''}`;
  const footer = [`<sub>${scanned}${aiNote ? ` · ${aiNote}` : ''}. To silence a finding, put a <code>shipwarden-ignore</code> comment on the line above it.</sub>`];

  if (!findings.length) return [MARKER, '### ✅ ShipWarden: no security issues found', '', ...checklistMarkdown(result.checklist), ...footer].join('\n');

  const shown = findings.slice(0, maxItems);
  const where = (f) => (link ? `[\`${f.file}:${f.line}\`](${link(f.file, f.line)})` : `\`${f.file}:${f.line}\``);
  const out = [
    MARKER,
    `### 🛡️ ShipWarden found ${plural(findings.length, 'security issue')}`,
    '',
    `**${summaryLine(findings)}**`,
    '',
    '| | Issue | Where |',
    '|---|---|---|',
    ...shown.map((f) => `| ${ICON[f.severity]} | ${cell(f.title)} | ${where(f)} |`),
    '',
  ];
  if (findings.length > shown.length) out.push(`_…and ${findings.length - shown.length} more. Run \`npx shipwarden\` locally for the full list._`, '');

  for (const f of shown) {
    out.push(
      `<details><summary>${ICON[f.severity]} <b>${f.title.replace(/`([^`]+)`/g, '<code>$1</code>')}</b> · <code>${f.file}:${f.line}</code></summary>`,
      '',
      f.message,
      '',
      `**How to fix:** ${f.ai?.fix || f.fix}`,
    );
    if (f.ai) out.push('', `> 🤖 AI review (${f.ai.verdict === 'real' ? 'confirmed' : 'unsure'}): ${f.ai.reason}`);
    out.push('', '</details>', '');
  }
  return [...out, ...checklistMarkdown(result.checklist), ...footer].join('\n');
}

function checklistSummary(items) {
  const done = items.filter((i) => i.ok).length;
  const mustMissing = items.filter((i) => !i.ok && i.priority === 'must').length;
  return `${done} of ${items.length} done${mustMissing ? ` · ${mustMissing} must-have${mustMissing === 1 ? '' : 's'} missing` : ''}`;
}

function checklistMarkdown(items = []) {
  if (!items.length) return [];
  const out = [`<details${items.some((i) => !i.ok && i.priority === 'must') ? ' open' : ''}><summary>📋 <b>Launch checklist</b>: ${checklistSummary(items)}</summary>`, ''];
  for (const i of items.filter((i) => !i.ok)) {
    const where = i.file ? ` (\`${i.file}:${i.line}\`)` : '';
    out.push(`- ${i.priority === 'must' ? '❌' : '⚠️'} **${i.missing}**${i.priority === 'must' ? ' · must have' : ''}${where}: ${i.why} **Fix:** ${i.fix}`);
  }
  const done = items.filter((i) => i.ok);
  if (done.length) out.push(`- ✅ ${done.map((i) => i.title).join(', ')}`);
  return [...out, '', '</details>', ''];
}

const escapeData = (s) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProp = (s) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'notice' };

/** GitHub workflow commands that show each finding inline on the PR diff. */
export function toAnnotations(findings) {
  return findings.map(
    (f) => `::${LEVEL[f.severity]} file=${escapeProp(f.file)},line=${f.line},title=${escapeProp(`ShipWarden: ${f.title.replace(/`/g, '')}`)}::${escapeData(`${f.message}\n\nFix: ${f.ai?.fix || f.fix}`)}`,
  );
}

const ANSI = { critical: '\x1b[41;97;1m', high: '\x1b[43;30;1m', medium: '\x1b[33;1m', low: '\x1b[37m', dim: '\x1b[2m', bold: '\x1b[1m', green: '\x1b[32;1m', reset: '\x1b[0m' };

export function toText(result, { color = false, aiNote } = {}) {
  const c = (code, s) => (color ? `${ANSI[code]}${s}${ANSI.reset}` : s);
  const strip = (s) => s.replace(/`/g, '');
  const head = `ShipWarden · scanned ${plural(result.filesScanned, 'file')}${result.stack.length ? ` (${result.stack.join(', ')})` : ''} in ${result.durationMs}ms${aiNote ? ` · ${aiNote}` : ''}`;
  const lines = [c('dim', head), ''];
  if (!result.findings.length) lines.push(c('green', '✔ No security issues found.'), '');
  for (const f of result.findings) {
    lines.push(
      `${c(f.severity, ` ${f.severity.toUpperCase()} `)} ${c('bold', strip(f.title))}`,
      `  ${c('dim', `${f.file}:${f.line}`)}`,
      `  ${strip(f.message)}`,
      `  ${c('bold', 'Fix:')} ${strip(f.ai?.fix || f.fix)}`,
    );
    if (f.ai) lines.push(`  ${c('dim', `AI review (${f.ai.verdict}): ${f.ai.reason}`)}`);
    lines.push('');
  }
  if (result.findings.length) lines.push(`${c('bold', `${plural(result.findings.length, 'issue')}:`)} ${summaryLine(result.findings)}`, '');

  const items = result.checklist ?? [];
  if (items.length) {
    lines.push(c('bold', `Launch checklist · ${checklistSummary(items)}`), '');
    for (const i of items.filter((i) => !i.ok)) {
      lines.push(
        ` ${i.priority === 'must' ? c('high', ' MUST HAVE ') : c('medium', 'NICE TO HAVE')} ${c('bold', i.missing)}${i.file ? c('dim', `  ${i.file}:${i.line}`) : ''}`,
        `  ${strip(i.why)}`,
        `  ${c('bold', 'Fix:')} ${strip(i.fix)}`,
        '',
      );
    }
    const done = items.filter((i) => i.ok);
    if (done.length) lines.push(`${c('green', ' ✔ Done:')} ${done.map((i) => i.title).join(' · ')}`, '');
  }
  return `${lines.join('\n')}`;
}

export function toJson(result, extra = {}) {
  const { fileContents, ...rest } = result;
  return JSON.stringify({ ...rest, ...extra }, null, 2);
}

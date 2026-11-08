import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { RULES, RULE_IDS } from './rules/index.js';
import { runChecklist } from './checklist.js';
import { TEST_FILE, globToRegExp, severityRank } from './util.js';

const DEFAULT_IGNORES = [
  'node_modules', '.git', '.next', '.nuxt', '.output', '.svelte-kit', '.vercel', '.netlify', '.turbo', '.cache',
  'dist', 'build', 'out', 'coverage', 'vendor', '*.min.js', '*.map',
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb',
];
const TEXT_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro',
  '.sql', '.rules', '.json', '.yml', '.yaml', '.toml', '.py', '.rb', '.go', '.php', '.html',
  '.md', '.txt', '.sh', '.ini', '.conf', '.xml', '.kt', '.swift', '.dart',
]);
const MAX_BYTES = 1024 * 1024;
const MAX_SQL_BYTES = 32 * 1024 * 1024; // schema dumps get big

function walk(root, rel = '', out = []) {
  for (const entry of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!DEFAULT_IGNORES.includes(entry.name)) walk(root, p, out);
    } else if (entry.isFile()) {
      out.push(p);
    }
  }
  return out;
}

/** Files git would commit (tracked + untracked-but-not-ignored); falls back to a directory walk. */
function listFiles(root) {
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      encoding: 'utf8',
      maxBuffer: 512 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return { paths: out.split('\0').filter(Boolean), tracked: true };
  } catch {
    return { paths: walk(root), tracked: false };
  }
}

/** `.shipwardenignore`: path globs, plus `check:<id>` lines that turn off a checklist item. */
function readIgnoreFile(root) {
  try {
    return fs
      .readFileSync(path.join(root, '.shipwardenignore'), 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch {
    return [];
  }
}

function loadFiles(root, paths, ignores) {
  const files = [];
  for (const rel of paths) {
    const base = rel.split('/').pop();
    if (!base.startsWith('.env') && !TEXT_EXT.has(path.extname(base).toLowerCase())) continue;
    if (ignores.some((re) => re.test(rel))) continue;
    const abs = path.join(root, rel);
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue; // tracked but deleted in the working tree
    }
    if (!stat.isFile() || stat.size > (rel.endsWith('.sql') ? MAX_SQL_BYTES : MAX_BYTES)) continue;
    const content = fs.readFileSync(abs, 'utf8');
    if (content.slice(0, 8000).includes('\0')) continue;
    files.push({ path: rel, content });
  }
  return files;
}

function detectKind(deps) {
  if (deps.has('next')) return 'next';
  if (deps.has('@sveltejs/kit')) return 'sveltekit';
  if (deps.has('nuxt')) return 'nuxt';
  if (deps.has('astro')) return 'astro';
  if ([...deps].some((d) => d.startsWith('@remix-run/'))) return 'remix';
  if (deps.has('vite') || deps.has('react-scripts')) return 'spa';
  return 'other';
}

function buildContext(files, tracked, paths) {
  const deps = new Set();
  for (const f of files) {
    if (!f.path.endsWith('package.json')) continue;
    try {
      const pkg = JSON.parse(f.content);
      for (const key of ['dependencies', 'devDependencies', 'peerDependencies']) {
        for (const name of Object.keys(pkg[key] ?? {})) deps.add(name);
      }
    } catch {
      // not valid JSON; ignore
    }
  }
  const anyPath = (re) => files.some((f) => re.test(f.path));
  const usesSupabase = [...deps].some((d) => d.startsWith('@supabase/')) || anyPath(/(^|\/)supabase\/(config\.toml|migrations\/|functions\/)/);
  const usesFirebase = deps.has('firebase') || deps.has('firebase-admin') || anyPath(/(^|\/)(firebase\.json|firestore\.rules)$/);
  const kind = detectKind(deps);
  // Only a plain SPA ships everything under src/ to the browser.
  const framework = kind === 'next' || kind === 'spa' ? kind : 'other';
  const app = kind !== 'other' || paths.some((p) => /(^|\/)index\.html$/.test(p));

  const stack = [];
  if (framework === 'next') stack.push('Next.js');
  if (framework === 'spa') stack.push(deps.has('vite') ? 'Vite' : 'React');
  if (usesSupabase) stack.push('Supabase');
  if (usesFirebase) stack.push('Firebase');
  if (deps.has('stripe') || deps.has('@stripe/stripe-js')) stack.push('Stripe');
  if (deps.has('@prisma/client') || deps.has('prisma')) stack.push('Prisma');
  const byPath = new Map(files.map((f) => [f.path, f.content]));
  return { tracked, deps, usesSupabase, usesFirebase, framework, kind, app, paths, stack, files: byPath };
}

const IGNORE_COMMENT = /shipwarden-ignore(?:[\s:]+([\w-]+(?:\s*,\s*[\w-]+)*))?/;

/** `shipwarden-ignore` (optionally followed by rule ids) on the finding's line or the line above. */
function isSuppressed(finding, fileContents) {
  const lines = fileContents.get(finding.file)?.split('\n') ?? [];
  for (const text of [lines[finding.line - 1], lines[finding.line - 2]]) {
    const m = text && IGNORE_COMMENT.exec(text);
    if (!m) continue;
    const ids = (m[1] ?? '').split(/\s*,\s*/).filter((id) => RULE_IDS.has(id));
    if (!ids.length || ids.includes(finding.ruleId)) return true;
  }
  return false;
}

/**
 * @param {string} root
 * @param {{ignore?: string[], checklist?: boolean, skipChecks?: string[]}} [opts]
 *   checklist: also run the whole-codebase launch checklist (skip it for PR-scoped scans).
 */
export async function scan(root, { ignore = [], checklist = true, skipChecks = [] } = {}) {
  const started = Date.now();
  const { paths, tracked } = listFiles(root);
  const ignoreLines = readIgnoreFile(root);
  const skip = new Set([...skipChecks, ...ignoreLines.filter((l) => l.startsWith('check:')).map((l) => l.slice(6).trim())]);
  const ignores = [...DEFAULT_IGNORES, ...ignoreLines.filter((l) => !l.startsWith('check:')), ...ignore].map(globToRegExp);
  const files = loadFiles(root, paths, ignores);
  const visiblePaths = paths.filter((p) => !ignores.some((re) => re.test(p)) && !TEST_FILE.test(p));
  const ctx = buildContext(files, tracked, visiblePaths);
  const fileContents = new Map(files.map((f) => [f.path, f.content]));

  const raw = [];
  for (const rule of RULES) {
    if (rule.checkAll) raw.push(...rule.checkAll(files, ctx));
    if (rule.check) for (const file of files) if (!TEST_FILE.test(file.path)) raw.push(...rule.check(file, ctx));
  }

  const seen = new Set();
  const findings = raw
    .filter((f) => {
      const key = `${f.ruleId}:${f.file}:${f.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return !isSuppressed(f, fileContents);
    })
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  return {
    root,
    filesScanned: files.length,
    stack: ctx.stack,
    findings,
    checklist: checklist ? runChecklist(files.filter((f) => !TEST_FILE.test(f.path)), ctx, skip) : [],
    fileContents,
    durationMs: Date.now() - started,
  };
}

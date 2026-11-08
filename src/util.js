export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Tests and fixtures are full of fake keys and deliberately unsafe code.
export const TEST_FILE = /(^|\/)(__tests__|__mocks__|__fixtures__|tests?|fixtures?|e2e|cypress|spec)\/|\.(test|spec|stories)\.[cm]?[jt]sx?$/;

export function severityRank(severity) {
  const i = SEVERITIES.indexOf(severity);
  return i === -1 ? SEVERITIES.length : i;
}

/** True when `severity` is at least as bad as `threshold` ("none" disables). */
export function atLeast(severity, threshold) {
  if (!threshold || threshold === 'none') return false;
  return severityRank(severity) <= severityRank(threshold);
}

const lineStarts = new Map();

export function lineAt(content, index) {
  let starts = lineStarts.get(content);
  if (!starts) {
    starts = [0];
    for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) starts.push(i + 1);
    lineStarts.set(content, starts);
  }
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Replace text with spaces but keep newlines, so offsets and line numbers stay valid. */
export function blank(text) {
  return text.replace(/[^\n]/g, ' ');
}

/** Does the file start with a directive such as 'use client' (after comments/whitespace)? */
export function hasDirective(content, directive) {
  const re = new RegExp(String.raw`^(?:\s|//[^\n]*\n|/\*[\s\S]*?\*/)*(['"])${directive}\1`);
  return re.test(content.slice(0, 4000));
}

/** Minimal .gitignore-style glob: `*`, `**`, `?`, trailing `/` for directories. */
export function globToRegExp(glob) {
  let g = glob.trim().replace(/^\.\//, '');
  if (g.endsWith('/')) g = g.slice(0, -1);
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') {
      if (g[i + 1] === '*') {
        if (g[i + 2] === '/') {
          re += '(?:.*/)?';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  // Like .gitignore: a pattern without a slash matches at any depth.
  const anchor = g.includes('/') ? '^' : '(?:^|/)';
  return new RegExp(`${anchor}${re}(?:/.*)?$`);
}

const PLACEHOLDER = /(x{4,}|\*{3,}|\.{3}|<|>|your|example|placeholder|dummy|sample|changeme|redacted|fake)/i;

export function looksLikePlaceholder(value) {
  return PLACEHOLDER.test(value) || /(.)\1{7,}/.test(value);
}

export function makeFinding(rule, file, line, fields = {}) {
  return {
    ruleId: rule.id,
    severity: fields.severity ?? rule.severity,
    confidence: fields.confidence ?? rule.confidence ?? 'high',
    title: fields.title ?? rule.title,
    file,
    line,
    message: fields.message ?? rule.message,
    fix: fields.fix ?? rule.fix,
  };
}

/** Code that ends up in the browser bundle. */
export function isClientCode(file, ctx) {
  if (!/\.[cm]?[jt]sx?$|\.(vue|svelte|astro)$/.test(file.path)) return false;
  if (hasDirective(file.content, 'use client')) return true;
  if (ctx.framework === 'spa') {
    return /(^|\/)src\//.test(file.path) && !/(^|\/)src\/(?:.*\/)?(server|api)\//.test(file.path);
  }
  return false;
}

export const ROUTE_HANDLER = /(^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/;
export const PAGES_API = /(^|\/)pages\/api\/.*\.[cm]?[jt]sx?$/;
export const EDGE_FUNCTION = /(^|\/)supabase\/functions\/[^/]+\/index\.[jt]sx?$/;

/** Code that runs as a public HTTP endpoint. */
export function isServerEndpoint(file) {
  return (
    ROUTE_HANDLER.test(file.path) ||
    PAGES_API.test(file.path) ||
    EDGE_FUNCTION.test(file.path) ||
    (/\.[cm]?[jt]sx?$/.test(file.path) && hasDirective(file.content, 'use server'))
  );
}

const SOURCE_EXT = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '/index.ts', '/index.tsx', '/index.js'];

function normalize(p) {
  const out = [];
  for (const part of p.split('/')) {
    if (part === '..') out.pop();
    else if (part && part !== '.') out.push(part);
  }
  return out.join('/');
}

/** The scanned file an import specifier points at: relative paths and the `@/` / `~/` aliases. */
function resolveImport(from, spec, ctx) {
  let bases;
  if (spec.startsWith('.')) {
    bases = [normalize(`${from.split('/').slice(0, -1).join('/')}/${spec}`)];
  } else if (/^[@~]\//.test(spec)) {
    // The alias points at the app root or its src/; in a monorepo that's the nearest package.json.
    const dirs = from.split('/').slice(0, -1);
    const roots = [''];
    for (let i = 1; i <= dirs.length; i++) {
      const dir = dirs.slice(0, i).join('/');
      if (ctx.files.has(`${dir}/package.json`)) roots.unshift(`${dir}/`);
    }
    bases = roots.flatMap((r) => [`${r}${spec.slice(2)}`, `${r}src/${spec.slice(2)}`]);
  } else {
    return null;
  }
  for (const base of bases) for (const ext of SOURCE_EXT) if (ctx.files.has(base + ext)) return base + ext;
  return null;
}

/** The source of one top-level function or const in a file, up to the next top-level declaration. */
function definition(content, name) {
  const m = new RegExp(String.raw`^(?:export\s+)?(?:(?:async\s+)?function\s*\*?\s*${name}\b|(?:const|let)\s+${name}\s*[=:])`, 'm').exec(content);
  if (!m) return null;
  const rest = content.slice(m.index + m[0].length);
  const next = /\n(?:export\s|(?:async\s+)?function\s|const\s|let\s|class\s)/.exec(rest);
  return m[0] + rest.slice(0, next ? next.index : 4000);
}

/**
 * Local helpers this file imports and calls, with their source, following one re-export:
 * `requireActor()` from `@/lib/auth` comes back as the text of `requireActor` in lib/auth.ts.
 */
export function importedHelpers(file, ctx) {
  if (!ctx?.files) return [];
  const body = file.content.replace(/^\s*import\b[\s\S]*?from\s*['"][^'"]+['"];?/gm, '');
  const out = [];
  for (const m of file.content.matchAll(/^\s*import\s+(?:type\s+)?([\w$]+)?\s*,?\s*(?:\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/gm)) {
    const names = [m[1], ...(m[2] ?? '').split(',').map((p) => p.trim().replace(/^type\s+/, ''))].filter(Boolean);
    const target = resolveImport(file.path, m[3], ctx);
    if (!target) continue;
    for (const spec of names) {
      const [imported, local = imported] = spec.replace(/\$/g, '\\$').split(/\s+as\s+/);
      if (!new RegExp(String.raw`\b${local}\s*\(`).test(body)) continue;
      let source = ctx.files.get(target);
      let def = imported === m[1] ? /export\s+default\b[\s\S]*/.exec(source)?.[0] : definition(source, imported);
      const reexport = !def && new RegExp(String.raw`export\s*\{[^}]*\b${imported}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`).exec(source);
      if (reexport) {
        const next = resolveImport(target, reexport[1], ctx);
        if (next) def = definition(ctx.files.get(next), imported);
      }
      if (def) out.push({ name: local, source: def });
    }
  }
  return out;
}

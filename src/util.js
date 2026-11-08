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

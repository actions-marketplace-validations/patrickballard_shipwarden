import { blank, lineAt, makeFinding } from '../util.js';

const WRITE_OPS = new Set(['write', 'create', 'update', 'delete']);
const READ_OPS = new Set(['read', 'get', 'list']);

function access(ops) {
  const reads = ops.some((op) => READ_OPS.has(op));
  const writes = ops.some((op) => WRITE_OPS.has(op));
  return reads && writes ? 'read and write' : writes ? 'write to' : 'read';
}
const ALLOW = /\ballow\s+(?<ops>[a-z]+(?:\s*,\s*[a-z]+)*)\s*(?<cond>:\s*if\b[^;]*)?;/g;
const MATCH_TOKEN = /match\s+((?:[^\s{]|\{[^}]*\})+)\s*\{|\{|\}/g;

function stripComments(rules) {
  return rules.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/\/\/[^\n]*/g, blank);
}

/** The `match` paths enclosing a position, outermost first. */
function matchPathsAt(rules, index) {
  const stack = [];
  for (const m of rules.matchAll(MATCH_TOKEN)) {
    if (m.index >= index) break;
    if (m[1]) stack.push(m[1]);
    else if (m[0] === '{') stack.push(null);
    else stack.pop();
  }
  return stack.filter(Boolean);
}

export const openRules = {
  id: 'firebase-open-rules',
  title: 'Firebase security rules are open',
  severity: 'critical',
  check(file) {
    if (!/(^|\/)(firestore|storage)\.rules$|\.rules$/.test(file.path)) return [];
    const rules = stripComments(file.content);
    const service = /service\s+firebase\.storage/.test(rules) ? 'Storage bucket' : 'database';
    const findings = [];
    for (const m of rules.matchAll(ALLOW)) {
      const ops = m.groups.ops.split(/\s*,\s*/);
      const writes = ops.some((op) => WRITE_OPS.has(op));
      const cond = (m.groups.cond ?? '').replace(/^:\s*if\s*/, '').trim();
      const paths = matchPathsAt(rules, m.index);
      const inner = paths.at(-1) ?? '';
      const catchAll = /\{\w+=\*\*\}/.test(inner);
      const topLevelCatchAll = catchAll && paths.length <= 2;
      const line = lineAt(file.content, m.index);
      const testMode = /request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/.exec(cond);

      if (cond === '' || cond === 'true') {
        if (!writes && (!catchAll || service !== 'database')) {
          findings.push(
            makeFinding(this, file.path, line, {
              severity: catchAll ? 'medium' : 'low',
              confidence: 'medium',
              title: catchAll ? `Anyone can read every file in your ${service}` : `Anyone can read \`${inner}\``,
              message: `These rules let anyone on the internet read ${catchAll ? `every file in your ${service}` : `\`${inner}\``} without signing in. Fine for truly public data (like product images), a leak for anything personal.`,
              fix: 'If this is user data, require ownership: `allow read: if request.auth != null && request.auth.uid == userId;`',
            }),
          );
          continue;
        }
        findings.push(
          makeFinding(this, file.path, line, {
            title: `Anyone can ${access(ops)} your ${service}`,
            message: `\`allow ${m.groups.ops}${cond ? ': if true' : ''}\` on \`${inner || '/'}\` lets anyone on the internet ${ops.join('/')} without signing in.${writes ? ' They can wipe or rewrite your data.' : ''}`,
            fix: 'Lock rules down per collection, e.g. `match /users/{userId} { allow read, write: if request.auth != null && request.auth.uid == userId; }`',
          }),
        );
      } else if (testMode) {
        const [, y, mo, d] = testMode;
        findings.push(
          makeFinding(this, file.path, line, {
            title: `Firebase "test mode" rules are still in place`,
            message: `Until ${y}-${mo.padStart(2, '0')}-${d.padStart(2, '0')} anyone can ${ops.join('/')} your entire ${service}. After that date every request is denied and the app stops working.`,
            fix: 'Replace the `request.time < timestamp.date(...)` rule with real per-collection rules before launch.',
          }),
        );
      } else if (topLevelCatchAll && /^request\.auth(\.uid)?\s*!=\s*null$/.test(cond)) {
        findings.push(
          makeFinding(this, file.path, line, {
            severity: 'high',
            title: `Any signed-in user can ${access(ops)} your whole ${service}`,
            message: `This catch-all rule only checks that the caller is signed in. Anyone can create a free account in your app and then ${ops.join('/')} every other user's data.`,
            fix: 'Replace the catch-all with per-collection rules that check ownership, e.g. `request.auth.uid == resource.data.ownerId`.',
          }),
        );
      }
    }
    return findings;
  },
};

export const openRealtimeDb = {
  id: 'firebase-rtdb-open',
  title: 'Realtime Database rules are open',
  severity: 'critical',
  check(file) {
    if (!/(^|\/)database\.rules\.json$/.test(file.path)) return [];
    const findings = [];
    for (const m of file.content.matchAll(/"\.(read|write)"\s*:\s*(?:true|"true")/g)) {
      const write = m[1] === 'write';
      findings.push(
        makeFinding(this, file.path, lineAt(file.content, m.index), {
          severity: write ? 'critical' : 'high',
          title: `Anyone can ${m[1]} your Realtime Database`,
          message: `\`".${m[1]}": true\` lets anyone on the internet ${m[1]} this part of your database without signing in.`,
          fix: 'Use `"auth != null && auth.uid === $uid"` style rules scoped to each user\'s data.',
        }),
      );
    }
    return findings;
  },
};

export default [openRules, openRealtimeDb];

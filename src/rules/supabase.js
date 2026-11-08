import { blank, lineAt, makeFinding } from '../util.js';

const IDENT = String.raw`(?:"[^"]+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(?<name>${IDENT}(?:\s*\.\s*${IDENT})?)`;

const STATEMENTS = {
  createTable: new RegExp(String.raw`\bcreate\s+(?:(?:global|local)\s+)?(?<temp>temp(?:orary)?\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QNAME}`, 'gi'),
  dropTable: new RegExp(String.raw`\bdrop\s+table\s+(?:if\s+exists\s+)?${QNAME}`, 'gi'),
  toggleRls: new RegExp(String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+(?<mode>enable|disable)\s+row\s+level\s+security`, 'gi'),
  createView: new RegExp(String.raw`\bcreate\s+(?:or\s+replace\s+)?(?<mat>materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?${QNAME}(?<rest>[^;]*)`, 'gi'),
  alterView: new RegExp(String.raw`\balter\s+view\s+(?:if\s+exists\s+)?${QNAME}\s+set\s*\((?<opts>[^)]*)\)`, 'gi'),
  dropView: new RegExp(String.raw`\bdrop\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?${QNAME}`, 'gi'),
};

// Matched with DO-block bodies kept: Lovable/AI migrations often wrap these in `DO $$ BEGIN ... END $$`.
const IN_BLOCKS = {
  toggleRls: STATEMENTS.toggleRls,
  createPolicy: new RegExp(String.raw`\bcreate\s+policy\s+(?<policy>"[^"]+"|[\w$]+)\s+on\s+${QNAME}(?<body>[^;]*)`, 'gi'),
  dropPolicy: new RegExp(String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?(?<policy>"[^"]+"|[\w$]+)\s+on\s+${QNAME}`, 'gi'),
};
delete STATEMENTS.toggleRls;

const DYNAMIC_RLS = /format\s*\(\s*'+[^']*?%I\s+enable\s+row\s+level\s+security/gi;
const DO_START = /\bdo\s*(\$\w*\$)/gi;

/**
 * `execute format('alter table public.%I enable row level security', t)` inside a DO block.
 * Returns the tables it covers: explicit names from the loop's array, or every table when it
 * iterates over the catalog.
 */
function dynamicRls(text) {
  const out = [];
  for (const m of text.matchAll(DYNAMIC_RLS)) {
    let start = Math.max(0, m.index - 3000);
    let end = m.index + 500;
    for (const d of text.matchAll(DO_START)) {
      if (d.index > m.index) break;
      start = d.index;
      const close = text.indexOf(d[1], d.index + d[0].length);
      end = close === -1 ? text.length : close;
    }
    const block = text.slice(start, end);
    const all = /pg_tables|information_schema\.tables|pg_class/i.test(block);
    const names = [...block.matchAll(/'([A-Za-z_][\w$]*)'/g)].map((n) => n[1].toLowerCase()).filter((n) => n !== 'public');
    out.push({ index: m.index, all, names });
  }
  return out;
}

/** Blank out comments and (unless keepBodies) dollar-quoted bodies, keeping offsets intact. */
export function cleanSql(sql, { keepBodies = false } = {}) {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    const n = sql[i + 1];
    let j;
    if (c === '-' && n === '-') {
      j = sql.indexOf('\n', i);
      if (j === -1) j = sql.length;
      out += blank(sql.slice(i, j));
    } else if (c === '/' && n === '*') {
      j = sql.indexOf('*/', i + 2);
      j = j === -1 ? sql.length : j + 2;
      out += blank(sql.slice(i, j));
    } else if (c === "'") {
      j = i + 1;
      while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
      j = Math.min(j + 1, sql.length);
      out += sql.slice(i, j);
    } else if (!keepBodies && c === '$' && /^\$(?:[A-Za-z_]\w*)?\$/.test(sql.slice(i, i + 64))) {
      const tag = /^\$(?:[A-Za-z_]\w*)?\$/.exec(sql.slice(i, i + 64))[0];
      const end = sql.indexOf(tag, i + tag.length);
      j = end === -1 ? sql.length : end + tag.length;
      out += blank(sql.slice(i, j));
    } else {
      j = i + 1;
      out += c;
    }
    i = j;
  }
  return out;
}

function parseName(raw) {
  const parts = raw.match(/"[^"]+"|[A-Za-z_][\w$]*/g).map((p) => (p.startsWith('"') ? p.slice(1, -1) : p.toLowerCase()));
  return parts.length > 1 ? { schema: parts[0], name: parts[1] } : { schema: 'public', name: parts[0] };
}

function invokerOn(opts) {
  const m = /security_invoker(?:\s*=\s*'?(\w+)'?)?/i.exec(opts ?? '');
  return !!m && (!m[1] || /^(true|on|1|yes)$/i.test(m[1]));
}

const cache = new WeakMap();

/**
 * Replay the migrations in order to work out the final state of tables, views and policies.
 * When the repo has supabase/migrations, only those count: other .sql files are usually
 * backups, snapshots or docs. RLS enabled in *any* .sql file still clears a table, because a
 * false "your data is public" alarm costs more trust than a missed one.
 */
function analyze(files) {
  if (cache.has(files)) return cache.get(files);
  const sql = files.filter((f) => f.path.endsWith('.sql'));
  const migrations = sql.filter((f) => /(^|\/)supabase\/(migrations|schemas)\//.test(f.path));
  const replayed = (migrations.length ? migrations : sql).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const enabledAnywhere = new Set();
  for (const file of sql) {
    for (const m of cleanSql(file.content, { keepBodies: true }).matchAll(IN_BLOCKS.toggleRls)) {
      const { schema, name } = parseName(m.groups.name);
      if (m.groups.mode.toLowerCase() === 'enable') enabledAnywhere.add(`${schema}.${name}`);
    }
    for (const d of dynamicRls(cleanSql(file.content, { keepBodies: true }))) {
      for (const n of d.names) enabledAnywhere.add(`public.${n}`);
    }
  }

  const events = [];
  replayed.forEach((file, fi) => {
    const groups = [
      [cleanSql(file.content), STATEMENTS],
      [cleanSql(file.content, { keepBodies: true }), IN_BLOCKS],
    ];
    for (const [text, statements] of groups) {
      for (const [kind, re] of Object.entries(statements)) {
        for (const m of text.matchAll(re)) events.push({ fi, kind, m, file });
      }
    }
    for (const d of dynamicRls(groups[1][0])) events.push({ fi, kind: 'dynamicRls', m: { index: d.index }, d, file });
  });
  events.sort((a, b) => a.fi - b.fi || a.m.index - b.m.index);

  const tables = new Map();
  const views = new Map();
  const policies = new Map();
  for (const { kind, m, file, d } of events) {
    if (kind === 'dynamicRls') {
      for (const t of tables.values()) if (t.schema === 'public' && (d.all || d.names.includes(t.name.toLowerCase()))) t.rls = true;
      continue;
    }
    const { schema, name } = parseName(m.groups.name);
    const key = `${schema}.${name}`;
    const loc = { file: file.path, line: lineAt(file.content, m.index) };
    if (kind === 'createTable') {
      const parent = new RegExp(String.raw`^\s*partition\s+of\s+${QNAME}`, 'i').exec(file.content.slice(m.index + m[0].length, m.index + m[0].length + 300));
      const partitionOf = parent && parseName(parent.groups.name).name;
      if (!m.groups.temp && !tables.has(key)) tables.set(key, { schema, name, rls: false, partitionOf, ...loc });
    } else if (kind === 'dropTable') {
      tables.delete(key);
    } else if (kind === 'toggleRls') {
      const enable = m.groups.mode.toLowerCase() === 'enable';
      const table = tables.get(key) ?? { schema, name, ...loc };
      table.rls = enable;
      if (!enable) Object.assign(table, loc, { disabledExplicitly: true });
      tables.set(key, table);
    } else if (kind === 'createView') {
      const withOpts = /^\s*with\s*\(([^)]*)\)/i.exec(m.groups.rest)?.[1];
      views.set(key, { schema, name, materialized: !!m.groups.mat, invoker: invokerOn(withOpts), ...loc });
    } else if (kind === 'alterView') {
      const view = views.get(key);
      if (view && invokerOn(m.groups.opts)) view.invoker = true;
    } else if (kind === 'dropView') {
      views.delete(key);
    } else if (kind === 'createPolicy') {
      policies.set(`${key}:${m.groups.policy}`, { schema, name, body: m.groups.body, ...loc });
    } else if (kind === 'dropPolicy') {
      policies.delete(`${key}:${m.groups.policy}`);
    }
  }
  for (const [key, t] of tables) {
    if (!t.rls && !t.disabledExplicitly && enabledAnywhere.has(key)) t.rls = true;
  }
  const result = { tables, views, policies: [...policies.values()] };
  cache.set(files, result);
  return result;
}

export const rlsDisabled = {
  id: 'supabase-rls-disabled',
  title: 'Row Level Security is off',
  severity: 'critical',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    const findings = [];
    const partitions = new Map();
    for (const t of analyze(files).tables.values()) {
      if (t.rls || t.schema !== 'public') continue;
      if (t.partitionOf) {
        if (!partitions.has(t.partitionOf)) partitions.set(t.partitionOf, []);
        partitions.get(t.partitionOf).push(t);
        continue;
      }
      findings.push(
        makeFinding(this, t.file, t.line, {
          title: `Row Level Security is off for table \`${t.name}\``,
          message:
            `${t.disabledExplicitly ? 'This migration turns Row Level Security off' : 'This table is created without Row Level Security'}. ` +
            'Supabase serves every table in the `public` schema through its API, and your anon key is public (it is in your frontend), ' +
            `so anyone can read, change or delete every row in \`${t.name}\`.`,
          fix:
            `Add a migration with \`alter table public.${t.name} enable row level security;\` and then policies that limit rows to their owner, ` +
            `e.g. \`create policy "Owners can read" on public.${t.name} for select using (auth.uid() = user_id);\``,
        }),
      );
    }
    for (const [parent, parts] of partitions) {
      const [first] = parts;
      findings.push(
        makeFinding(this, first.file, first.line, {
          title: `Row Level Security is off for ${parts.length} partition${parts.length === 1 ? '' : 's'} of \`${parent}\``,
          message:
            `${parts.map((t) => `\`${t.name}\``).slice(0, 4).join(', ')}${parts.length > 4 ? ` and ${parts.length - 4} more` : ''} have no Row Level Security. ` +
            "Supabase's API serves each partition as its own table, and the parent table's policies don't apply when a partition is queried directly.",
          fix: `Enable RLS on every partition (\`alter table public.<partition> enable row level security;\`), or revoke API access to them: \`revoke all on public.<partition> from anon, authenticated;\``,
        }),
      );
    }
    return findings;
  },
};

export const permissivePolicy = {
  id: 'supabase-permissive-policy',
  title: 'RLS policy allows everyone',
  severity: 'high',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    const findings = [];
    for (const p of analyze(files).policies) {
      if (p.schema !== 'public' || /\bas\s+restrictive\b/i.test(p.body)) continue;
      const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(p.body)?.[1] ?? 'all').toLowerCase();
      const rolesRaw = /\bto\s+((?:"[^"]+"|[\w$]+)(?:\s*,\s*(?:"[^"]+"|[\w$]+))*)/i.exec(p.body)?.[1];
      const roles = rolesRaw ? rolesRaw.split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase()) : ['public'];
      if (roles.every((r) => ['service_role', 'postgres', 'supabase_admin'].includes(r))) continue;
      const usingTrue = /\busing\s*\(\s*true\s*\)/i.test(p.body);
      const checkTrue = /\bwith\s+check\s*\(\s*true\s*\)/i.test(p.body);
      const anyone = roles.some((r) => r === 'public' || r === 'anon');
      const who = anyone ? 'anyone, even logged-out visitors,' : 'any logged-in user';
      const whoShort = anyone ? 'anyone' : 'any logged-in user';

      if (['all', 'update', 'delete'].includes(cmd) && usingTrue) {
        const verb = { all: 'read, change and delete', update: 'change', delete: 'delete' }[cmd];
        findings.push(
          makeFinding(this, p.file, p.line, {
            title: `RLS policy lets ${whoShort} ${verb} any row in \`${p.name}\``,
            message: `\`using (true)\` never checks who owns the row, so this policy lets ${who} ${verb} every row in \`${p.name}\`.`,
            fix: 'Replace `true` with an ownership check, e.g. `using (auth.uid() = user_id) with check (auth.uid() = user_id)`.',
          }),
        );
      } else if (cmd === 'insert' && checkTrue) {
        findings.push(
          makeFinding(this, p.file, p.line, {
            severity: 'low',
            confidence: 'medium',
            title: `RLS policy lets ${whoShort} insert anything into \`${p.name}\``,
            message: `\`with check (true)\` lets ${who} insert rows with any values, including someone else's \`user_id\`. Fine for a public form, risky for user-owned data.`,
            fix: 'If rows belong to a user, use `with check (auth.uid() = user_id)`.',
          }),
        );
      }
    }
    return findings;
  },
};

export const unsafeView = {
  id: 'supabase-view-bypasses-rls',
  title: 'View bypasses Row Level Security',
  severity: 'medium',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    const findings = [];
    for (const v of analyze(files).views.values()) {
      if (v.schema !== 'public' || v.invoker) continue;
      findings.push(
        makeFinding(this, v.file, v.line, {
          title: `View \`${v.name}\` bypasses Row Level Security`,
          message: v.materialized
            ? `Materialized views ignore RLS, and \`${v.name}\` is in the \`public\` schema, so anyone with your anon key can read all of it through the API.`
            : `Views run with their creator's permissions by default, so \`${v.name}\` ignores the RLS policies on the tables it reads and anyone with your anon key can query it.`,
          fix: v.materialized
            ? `Move it to a schema that isn't exposed (e.g. \`private\`), or revoke access: \`revoke select on public.${v.name} from anon, authenticated;\``
            : `Recreate it with \`create view public.${v.name} with (security_invoker = true) as ...\` (Postgres 15+), or \`alter view public.${v.name} set (security_invoker = true);\``,
        }),
      );
    }
    return findings;
  },
};

export default [rlsDisabled, permissivePolicy, unsafeView];

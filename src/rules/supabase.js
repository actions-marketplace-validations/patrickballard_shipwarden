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
  // Bodies are blanked here, so `[^;]*` runs to the end of the statement and sees every attribute.
  createFunction: new RegExp(String.raw`\bcreate\s+(?:or\s+replace\s+)?(?:function|procedure)\s+${QNAME}\s*\((?<rest>[^;]*)`, 'gi'),
  alterFunction: new RegExp(String.raw`\balter\s+(?:function|procedure)\s+${QNAME}(?<rest>[^;]*)`, 'gi'),
  dropFunction: new RegExp(String.raw`\bdrop\s+(?:function|procedure)\s+(?:if\s+exists\s+)?${QNAME}`, 'gi'),
  grant: /\b(?<verb>grant|revoke)\s+(?<privs>[\w\s,]*?)\s+on\s+(?<targets>[^;]*?)\s+(?:to|from)\s+(?<roles>[^;]+)/gi,
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

/** Apply `grant/revoke select on <views> to/from anon, authenticated` to the views it names. */
function applyGrant(views, m) {
  const { verb, privs, targets, roles } = m.groups;
  if (!/\b(select|all)\b/i.test(privs)) return;
  const who = roles
    .replace(/\b(cascade|restrict|with\s+grant\s+option|granted\s+by\s+\w+)\b/gi, '')
    .split(',')
    .map((r) => r.trim().replace(/"/g, '').toLowerCase())
    .filter((r) => r === 'anon' || r === 'authenticated');
  const schemaWide = /\ball\s+tables\s+in\s+schema\s+((?:"[^"]+"|\w+)(?:\s*,\s*(?:"[^"]+"|\w+))*)/i.exec(targets);
  const hit = schemaWide
    ? [...views.values()].filter((v) => schemaWide[1].split(',').map((n) => n.trim().replace(/"/g, '').toLowerCase()).includes(v.schema))
    : targets
        .replace(/^\s*table\s+/i, '')
        .split(',')
        .map((t) => (/^\s*(?:"[^"]+"|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][\w$]*))?\s*$/.test(t) ? parseName(t) : null))
        .map((t) => t && views.get(`${t.schema}.${t.name}`))
        .filter(Boolean);
  for (const view of hit) for (const role of who) view.revoked[verb.toLowerCase() === 'revoke' ? 'add' : 'delete'](role);
}

function invokerOn(opts) {
  const m = /security_invoker(?:\s*=\s*'?(\w+)'?)?/i.exec(opts ?? '');
  return !!m && (!m[1] || /^(true|on|1|yes)$/i.test(m[1]));
}

/** The text inside `using (...)` or `with check (...)`, with nested parentheses. */
function clause(body, keyword) {
  const m = new RegExp(String.raw`\b${keyword}\s*\(`, 'i').exec(body);
  if (!m) return null;
  let depth = 1;
  let i = m.index + m[0].length;
  for (; i < body.length && depth; i++) depth += body[i] === '(' ? 1 : body[i] === ')' ? -1 : 0;
  return body.slice(m.index + m[0].length, i - 1);
}

function policyInfo(body) {
  const rolesRaw = /\bto\s+((?:"[^"]+"|[\w$]+)(?:\s*,\s*(?:"[^"]+"|[\w$]+))*)/i.exec(body)?.[1];
  return {
    cmd: (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(body)?.[1] ?? 'all').toLowerCase(),
    roles: rolesRaw ? rolesRaw.split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase()) : ['public'],
    using: clause(body, 'using'),
    check: clause(body, String.raw`with\s+check`),
  };
}

const ADMIN_ROLES = ['service_role', 'postgres', 'supabase_admin'];

/** `id -> public` for buckets created in SQL. Buckets made in the dashboard are unknown. */
function buckets(sqlFiles) {
  const out = new Map();
  const re = /\binsert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*((?:\([^)]*\)\s*,?\s*)+)/gi;
  for (const file of sqlFiles) {
    for (const m of cleanSql(file.content, { keepBodies: true }).matchAll(re)) {
      const cols = m[1].split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase());
      const id = cols.indexOf('id') === -1 ? cols.indexOf('name') : cols.indexOf('id');
      const pub = cols.indexOf('public');
      for (const row of m[2].matchAll(/\(([^)]*)\)/g)) {
        const values = row[1].match(/'(?:[^']|'')*'|[^,]+/g)?.map((v) => v.trim().replace(/^'|'$/g, '')) ?? [];
        if (values[id]) out.set(values[id], pub !== -1 && /^true$/i.test(values[pub] ?? ''));
      }
    }
  }
  return out;
}

// "Logged in" conditions that don't tie a file to its owner.
const LOGGED_IN = /\(?\s*(?:select\s+)?auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s*is\s+not\s+null|auth\s*\.\s*role\s*\(\s*\)\s*=\s*'authenticated'/gi;
const PATH_FUNCTIONS = new Set(['storage.foldername', 'storage.filename', 'storage.extension', 'lower', 'upper', 'coalesce', 'in', 'and', 'or', 'not', 'array']);

/**
 * Whether a storage policy condition limits access to some user. Any call we don't recognise
 * (a custom `is_admin()`, a subquery) counts as a check, so we stay quiet when unsure.
 */
function checksUser(expr) {
  const rest = expr.replace(LOGGED_IN, ' ');
  if (/\bauth\s*\.\s*(?:uid|jwt)\s*\(|\bowner(?:_id)?\b|\bexists\s*\(|\bselect\b/i.test(rest)) return true;
  return [...rest.matchAll(/([A-Za-z_][\w$]*(?:\s*\.\s*[A-Za-z_][\w$]*)?)\s*\(/g)].some((m) => !PATH_FUNCTIONS.has(m[1].replace(/\s+/g, '').toLowerCase()));
}

function bucketsIn(expr) {
  const out = [];
  for (const m of expr.matchAll(/\bbucket_id\s*(?:=\s*'([^']+)'|in\s*\(([^)]*)\))/gi)) {
    if (m[1]) out.push(m[1]);
    else out.push(...[...m[2].matchAll(/'([^']+)'/g)].map((b) => b[1]));
  }
  return out;
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
  const functions = new Map();
  for (const { kind, m, file, d } of events) {
    if (kind === 'grant') {
      applyGrant(views, m);
      continue;
    }
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
      // `create or replace` keeps the view's grants.
      const revoked = views.get(key)?.revoked ?? new Set();
      views.set(key, { schema, name, materialized: !!m.groups.mat, invoker: invokerOn(withOpts), body: m.groups.rest, revoked, ...loc });
    } else if (kind === 'alterView') {
      const view = views.get(key);
      if (view && invokerOn(m.groups.opts)) view.invoker = true;
    } else if (kind === 'dropView') {
      views.delete(key);
    } else if (kind === 'createPolicy') {
      policies.set(`${key}:${m.groups.policy}`, { schema, name, body: m.groups.body, ...loc });
    } else if (kind === 'dropPolicy') {
      policies.delete(`${key}:${m.groups.policy}`);
    } else if (kind === 'createFunction') {
      const { rest } = m.groups;
      functions.set(key, { schema, name, definer: /\bsecurity\s+definer\b/i.test(rest), pinned: /\bset\s+search_path\b/i.test(rest), ...loc });
    } else if (kind === 'alterFunction') {
      const fn = functions.get(key);
      if (!fn) continue;
      if (/\bset\s+search_path\b/i.test(m.groups.rest)) fn.pinned = true;
      if (/\bsecurity\s+invoker\b/i.test(m.groups.rest)) fn.definer = false;
      if (/\bsecurity\s+definer\b/i.test(m.groups.rest)) fn.definer = true;
    } else if (kind === 'dropFunction') {
      functions.delete(key);
    }
  }
  for (const [key, t] of tables) {
    if (!t.rls && !t.disabledExplicitly && enabledAnywhere.has(key)) t.rls = true;
  }
  const result = { tables, views, functions, policies: [...policies.values()], buckets: buckets(sql) };
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
      const { cmd, roles } = policyInfo(p.body);
      if (roles.every((r) => ADMIN_ROLES.includes(r))) continue;
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

// The view's own query limits rows to the caller: often a deliberate column-hiding view.
const FILTERS_CALLER = /\bauth\s*\.\s*(?:uid|jwt|role)\s*\(|current_setting\s*\(\s*'request\.jwt|\bwhere\b[\s\S]*\b\w*(?:user|member|tenant|access|owner|can_|is_|has_)\w*\s*\(/i;

export const unsafeView = {
  id: 'supabase-view-bypasses-rls',
  title: 'View bypasses Row Level Security',
  severity: 'medium',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    const findings = [];
    for (const v of analyze(files).views.values()) {
      if (v.schema !== 'public' || v.invoker) continue;
      const anonRevoked = v.revoked.has('anon');
      if (anonRevoked && v.revoked.has('authenticated')) continue;
      const fix = v.materialized
        ? `Move it to a schema that isn't exposed (e.g. \`private\`), or revoke access: \`revoke select on public.${v.name} from anon, authenticated;\``
        : `Recreate it with \`create view public.${v.name} with (security_invoker = true) as ...\` (Postgres 15+), or \`alter view public.${v.name} set (security_invoker = true);\``;
      // A materialized view's filter runs at refresh time, not per caller, so it doesn't count.
      const filtered = !v.materialized && FILTERS_CALLER.test(v.body ?? '');
      if (filtered || anonRevoked) {
        findings.push(
          makeFinding(this, v.file, v.line, {
            severity: 'low',
            confidence: 'medium',
            title: filtered
              ? `Check that view \`${v.name}\` only returns the caller's rows`
              : `Any logged-in user can read every row of view \`${v.name}\``,
            message: filtered
              ? `\`${v.name}\` skips the RLS policies on the tables it reads, but its own query filters by the current user, so this is probably deliberate (for example a view that hides some columns). Make sure that filter covers every row it can return.`
              : `Logged-out visitors can't query \`${v.name}\` (anon access is revoked), but it still skips the RLS policies on the tables it reads, so any signed-in user can read every row, including other users' and other teams'. That's fine if the data is meant to be shared.`,
            fix,
          }),
        );
        continue;
      }
      findings.push(
        makeFinding(this, v.file, v.line, {
          title: `View \`${v.name}\` bypasses Row Level Security`,
          message: v.materialized
            ? `Materialized views ignore RLS, and \`${v.name}\` is in the \`public\` schema, so anyone with your anon key can read all of it through the API.`
            : `Views run with their creator's permissions by default, so \`${v.name}\` ignores the RLS policies on the tables it reads and anyone with your anon key can query it.`,
          fix,
        }),
      );
    }
    return findings;
  },
};

export const storagePolicy = {
  id: 'supabase-storage-policy',
  title: 'Storage policy lets anyone change files',
  severity: 'high',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    const { policies, buckets: known } = analyze(files);
    const findings = [];
    for (const p of policies) {
      if (p.schema !== 'storage' || p.name !== 'objects' || /\bas\s+restrictive\b/i.test(p.body)) continue;
      const { cmd, roles, using, check } = policyInfo(p.body);
      if (roles.every((r) => ADMIN_ROLES.includes(r))) continue;
      const expr = (cmd === 'insert' ? check : using ?? check) ?? 'true';
      if (checksUser(expr)) continue;

      const anyone = roles.some((r) => r === 'public' || r === 'anon') && expr.replace(LOGGED_IN, '') === expr;
      const who = anyone ? 'anyone' : 'any logged-in user';
      const ids = bucketsIn(expr);
      const where = ids.length === 0 ? 'every bucket' : ids.length === 1 ? `the \`${ids[0]}\` bucket` : `the ${ids.map((b) => `\`${b}\``).join(', ')} buckets`;
      const bucket = ids[0] ?? 'your-bucket';
      const ownerFix =
        `Store each user's files under a folder named after their id and check it, e.g. ` +
        `\`using (bucket_id = '${bucket}' and (storage.foldername(name))[1] = auth.uid()::text)\`.`;

      if (['all', 'update', 'delete'].includes(cmd)) {
        const verb = { all: 'read, overwrite and delete', update: 'overwrite', delete: 'delete' }[cmd];
        findings.push(
          makeFinding(this, p.file, p.line, {
            severity: anyone ? 'high' : 'medium',
            title: `Storage policy lets ${who} ${verb} any file in ${where}`,
            message: `This policy on \`storage.objects\` never checks who uploaded a file, so ${anyone ? 'anyone with your public anon key' : 'any logged-in user'} can ${verb} every file in ${where}, including other users' files.`,
            fix: ownerFix,
          }),
        );
      } else if (cmd === 'insert' && anyone) {
        findings.push(
          makeFinding(this, p.file, p.line, {
            severity: 'low',
            title: `Storage policy lets anyone upload files to ${where}`,
            message: `Logged-out visitors can upload any file to ${where} using your public anon key: people can fill your storage (and your bill) or use it to host their own files.`,
            fix: `Add \`to authenticated\` to the policy, and ideally limit uploads to the user's own folder: \`with check (bucket_id = '${bucket}' and (storage.foldername(name))[1] = auth.uid()::text)\`.`,
          }),
        );
      } else if (cmd === 'select') {
        // Reading a public bucket is expected; only private buckets created in SQL are known to be private.
        const exposed = (ids.length ? ids : [...known.keys()]).filter((b) => known.get(b) === false);
        if (!exposed.length) continue;
        const label = exposed.length === 1 ? `the private \`${exposed[0]}\` bucket` : `the private ${exposed.map((b) => `\`${b}\``).join(', ')} buckets`;
        findings.push(
          makeFinding(this, p.file, p.line, {
            severity: anyone ? 'high' : 'medium',
            title: `Storage policy lets ${who} read every file in ${label}`,
            message: `The bucket is private, but this policy lets ${anyone ? 'anyone with your public anon key' : 'any logged-in user'} list and download every file in it, including other users' files.`,
            fix: ownerFix,
          }),
        );
      }
    }
    return findings;
  },
};

export const definerSearchPath = {
  id: 'supabase-definer-search-path',
  title: 'SECURITY DEFINER function without a fixed search_path',
  severity: 'low',
  checkAll(files, ctx) {
    if (!ctx.usesSupabase) return [];
    // One finding per migration file: AI-written migrations often define a dozen of these at once.
    const byFile = new Map();
    for (const fn of analyze(files).functions.values()) {
      if (!fn.definer || fn.pinned) continue;
      if (!byFile.has(fn.file)) byFile.set(fn.file, []);
      byFile.get(fn.file).push(fn);
    }
    return [...byFile.values()].map((fns) => {
      const [first] = fns;
      const names = fns.map((f) => `\`${f.name}\``);
      const list = names.length > 4 ? `${names.slice(0, 4).join(', ')} and ${names.length - 4} more` : names.join(', ');
      return makeFinding(this, first.file, first.line, {
        title:
          fns.length === 1
            ? `Function \`${first.name}\` runs with its owner's privileges but has no fixed search_path`
            : `${fns.length} functions run with their owner's privileges but have no fixed search_path`,
        message:
          `${fns.length === 1 ? 'This function is' : `${list} are`} \`security definer\`, so ${fns.length === 1 ? 'it runs' : 'they run'} as the owner and skip Row Level Security. ` +
          "Without `set search_path`, tables and functions are looked up using the caller's search_path, so anyone who can create objects in a schema on that path " +
          "can make them run their code with the owner's privileges. Supabase's Security Advisor flags this too.",
        fix:
          `Add \`set search_path = ''\` to each function and write table names in full inside it (e.g. \`public.profiles\`), ` +
          `or run \`alter function ${first.schema}.${first.name} set search_path = '';\` for each one. \`set search_path = public\` also works if you'd rather not rename things.`,
      });
    });
  },
};

export default [rlsDisabled, permissivePolicy, unsafeView, storagePolicy, definerSearchPath];

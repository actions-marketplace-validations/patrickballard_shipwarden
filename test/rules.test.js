import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { scan } from '../src/scanner.js';
import { globToRegExp } from '../src/util.js';
import { browserFlag, hits, makeRepo, stripeLiveKey, supabaseJwt, supabasePkg, vitePkg } from './helpers.js';

test('Supabase: replays migrations to find tables without RLS, open policies and unsafe views', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/20240101000000_init.sql': `-- schema
create table public.profiles (id uuid primary key, email text);
create table if not exists "public"."posts" (id bigint, user_id uuid);
alter table public.posts enable row level security;
create table todos (id int);
create temporary table scratch (id int);
create table private.secrets (id int);
create or replace function public.handle() returns trigger as $$
begin
  create table should_not_count (id int);
  return new;
end;
$$ language plpgsql;
-- create table commented_out (id int);
/* create table also_commented (id int); */
create policy "delete anything" on public.posts for delete to authenticated using (true);
create policy "owners update" on public.posts for update using (auth.uid() = user_id);
create policy "public read" on public.posts for select using (true);
create policy "contact form" on public.messages for insert to anon with check (true);
create policy "admin" on public.posts for all to service_role using (true);
create view public.post_stats as select count(*) from posts;
create view public.safe_view with (security_invoker = true) as select 1;
create view public.fixed_later as select 1;
`,
    'supabase/migrations/20240202000000_more.sql': `alter table todos enable row level security;
alter table public.legacy disable row level security;
alter view public.fixed_later set (security_invoker = on);
`,
  });
  const result = await scan(root);
  const byRule = (id) => result.findings.filter((f) => f.ruleId === id);

  assert.deepEqual(
    byRule('supabase-rls-disabled').map((f) => [f.file.split('/').pop(), f.line]),
    [
      ['20240101000000_init.sql', 2],
      ['20240202000000_more.sql', 2],
    ],
  );
  assert.match(byRule('supabase-rls-disabled')[0].title, /profiles/);
  assert.match(byRule('supabase-rls-disabled')[1].message, /turns Row Level Security off/);

  const policies = byRule('supabase-permissive-policy');
  assert.equal(policies.length, 2);
  assert.equal(policies[0].severity, 'high');
  assert.match(policies[0].title, /any logged-in user delete any row in `posts`/);
  assert.equal(policies.find((f) => f.severity === 'low').title, 'RLS policy lets anyone insert anything into `messages`');

  assert.deepEqual(byRule('supabase-view-bypasses-rls').map((f) => f.title), ['View `post_stats` bypasses Row Level Security']);
});

test('Supabase rules stay quiet when the project does not use Supabase', async () => {
  const root = makeRepo({
    'package.json': JSON.stringify({ dependencies: { '@prisma/client': '6.0.0' } }),
    'prisma/migrations/1_init/migration.sql': 'CREATE TABLE "User" (id serial primary key);',
  });
  assert.deepEqual(hits(await scan(root)), []);
});

test('Firebase: open rules, test mode, signed-in catch-all and Realtime Database', async () => {
  const root = makeRepo({
    'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2025, 3, 1);
    }
  }
}`,
    'storage.rules': `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.auth != null;
    }
  }
}`,
    'other/firestore.rules': `service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read: if true;
      allow write: if true;
    }
    match /users/{userId} {
      // allow read, write: if true;
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}`,
    'database.rules.json': '{ "rules": { ".read": true, ".write": "auth != null" } }',
  });
  const found = (await scan(root)).findings.map((f) => [f.file, f.line, f.severity, f.title]);
  assert.deepEqual(
    found.map(([file, line, severity]) => `${severity} ${file}:${line}`).sort(),
    ['critical firestore.rules:5', 'critical other/firestore.rules:5', 'high database.rules.json:1', 'high storage.rules:5', 'low other/firestore.rules:4'].sort(),
  );
  assert.ok(found.some(([, , , title]) => title === 'Any signed-in user can read and write your whole Storage bucket'));
  assert.ok(found.some(([, , , title]) => title === 'Firebase "test mode" rules are still in place'));
});

test('Secrets: service_role JWTs, live keys and public env vars, but not anon keys or placeholders', async () => {
  const root = makeRepo({
    'package.json': vitePkg,
    'src/integrations/supabase/client.ts': `export const anon = "${supabaseJwt('anon')}";\nexport const admin = "${supabaseJwt('service_role')}";\n`,
    'server/pay.ts': `const stripe = new Stripe("${stripeLiveKey}");\nconst docs = "${['sk', 'live', 'x'.repeat(24)].join('_')}";\n`,
    '.env.example': 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\nVITE_OPENAI_API_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\nNEXT_PUBLIC_SITE_URL=\n',
    'src/lib/ai.ts': `import OpenAI from 'openai';\nexport const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, ${browserFlag} });\n`,
  });
  const result = await scan(root);
  assert.deepEqual(hits(result), [
    'ai-key-in-browser src/lib/ai.ts',
    'hardcoded-secret server/pay.ts',
    'public-env-secret .env.example',
    'public-env-secret .env.example',
    'supabase-service-role-key src/integrations/supabase/client.ts',
  ]);
  const jwt = result.findings.find((f) => f.ruleId === 'supabase-service-role-key');
  assert.equal(jwt.line, 2);
  assert.match(jwt.message, /shipped to every visitor's browser/);
  const severities = result.findings.filter((f) => f.ruleId === 'public-env-secret' && f.file === '.env.example').map((f) => f.severity);
  assert.deepEqual(severities, ['critical', 'high']);
});

test('Endpoints: flags writes with no auth check, skips protected and RLS-guarded ones', async () => {
  const admin = `import { createClient } from '@supabase/supabase-js';\nconst supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n`;
  const root = makeRepo({
    'package.json': supabasePkg,
    'app/api/admin/delete-user/route.ts': `${admin}export async function DELETE(req) {\n  const { id } = await req.json();\n  await supabase.from('profiles')\n    .delete().eq('id', id);\n  return Response.json({ ok: true });\n}\n`,
    'app/api/profile/route.ts': `${admin}export async function POST(req) {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response('no', { status: 401 });\n  await supabase.from('profiles').update({ name: 'x' }).eq('id', user.id);\n}\n`,
    'app/api/stats/route.ts': `${admin}export async function GET() {\n  await supabase.from('visits').insert({});\n}\n`,
    'app/api/notes/route.ts': `import { createClient } from '@/utils/supabase/server';\nexport async function POST() {\n  const supabase = await createClient();\n  await supabase.from('notes').insert({ body: 'hi' });\n}\n`,
    'app/actions.ts': `'use server';\nimport { prisma } from '@/lib/prisma';\nexport async function deleteAccount(id) {\n  await prisma.user.delete({ where: { id } });\n}\n`,
    'supabase/functions/admin-reset/index.ts': `import { createClient } from 'jsr:@supabase/supabase-js@2';\nDeno.serve(async (req) => {\n  const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n  await supabase.from('credits').update({ amount: 1000 }).neq('id', 0);\n  return new Response('ok');\n});\n`,
    'supabase/functions/cron/index.ts': `Deno.serve(async (req) => {\n  if (req.headers.get('x-secret') !== Deno.env.get('CRON_SECRET')) return new Response('no', { status: 401 });\n  const supabase = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n  await supabase.from('jobs').delete().lt('at', 1);\n});\n`,
    'app/api/stripe/webhook/route.ts': `import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\nexport async function POST(req) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') {}\n}\n`,
    'app/api/billing/webhook/route.ts': `import Stripe from 'stripe';\nexport async function POST(req) {\n  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature'), secret);\n}\n`,
    'middleware.ts': `export async function middleware(req) {\n  const { data } = await supabase.auth.getSession();\n}\n`,
    'app/dashboard/page.tsx': `export default async function Page() {\n  const { data } = await supabase.auth.getSession();\n  const { data: u } = await supabase.auth.getUser();\n}\n`,
  });
  const result = await scan(root);
  assert.deepEqual(hits(result), [
    'stripe-webhook-unverified app/api/stripe/webhook/route.ts',
    'supabase-getsession-on-server middleware.ts',
    'unauthenticated-write app/actions.ts',
    'unauthenticated-write app/api/admin/delete-user/route.ts',
    'unauthenticated-write supabase/functions/admin-reset/index.ts',
  ]);
  const del = result.findings.find((f) => f.file === 'app/api/admin/delete-user/route.ts');
  assert.equal(del.severity, 'high');
  assert.equal(del.line, 5);
  assert.equal(result.findings.find((f) => f.file === 'app/actions.ts').severity, 'medium');
});

test('XSS and SQL injection heuristics', async () => {
  const root = makeRepo({
    'components/Bio.tsx': 'export const Bio = ({ user }) => <div dangerouslySetInnerHTML={{ __html: user.bio }} />;\n',
    'components/Static.tsx': 'export const S = () => <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;\n',
    'components/Clean.tsx': "import DOMPurify from 'dompurify';\nexport const C = ({ html }) => <div dangerouslySetInnerHTML={{ __html: clean }} />;\n",
    'components/Seo.tsx': 'export const J = ({ data }) => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />;\n',
    'lib/db.ts': [
      "const a = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);",
      'const b = await pool.query(`select * from orders where id = ${req.query.id}`);',
      'const c = await pool.query("select * from t where name = \'" + name + "\'");',
      'const d = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;',
      "const e = await pool.query('select * from t where id = $1', [id]);",
    ].join('\n'),
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`).sort(),
    ['sql-injection lib/db.ts:1', 'sql-injection lib/db.ts:2', 'sql-injection lib/db.ts:3', 'xss-unsanitized-html components/Bio.tsx:1'],
  );
});

test('.env files: flags committed secrets, ignores gitignored, template and public-only files', async () => {
  const root = makeRepo(
    {
      '.gitignore': '.env.local\n',
      '.env': 'OPENAI_API_KEY=abc123\nVITE_SUPABASE_URL=https://x.supabase.co\n',
      '.env.local': 'STRIPE_SECRET_KEY=abc\n',
      '.env.example': 'OPENAI_API_KEY=\n',
      'web/.env': 'VITE_SUPABASE_URL=https://x.supabase.co\nVITE_SUPABASE_PUBLISHABLE_KEY=abc\n',
    },
    { git: true },
  );
  const result = await scan(root);
  assert.deepEqual(hits(result), ['env-file-committed .env']);
  assert.match(result.findings[0].message, /`OPENAI_API_KEY`/);
  assert.doesNotMatch(result.findings[0].message, /abc123/);
});

test('shipwarden-ignore comments and ignore globs', async () => {
  const root = makeRepo({
    '.shipwardenignore': '# fixtures\nfixtures/\n',
    'components/A.tsx': '// shipwarden-ignore: content is from our CMS\nexport const A = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />;\n',
    'components/B.tsx': '// shipwarden-ignore sql-injection\nexport const B = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />;\n',
    'components/C.tsx': 'export const C = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />; // shipwarden-ignore xss-unsanitized-html\n',
    'fixtures/D.tsx': 'export const D = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />;\n',
    'other/E.tsx': 'export const E = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />;\n',
  });
  assert.deepEqual(hits(await scan(root, { ignore: ['other/**'] })), ['xss-unsanitized-html components/B.tsx']);
});

test('a well-built app produces no findings', async () => {
  const root = makeRepo(
    {
      '.gitignore': '.env.local\n',
      'package.json': supabasePkg,
      '.env.local': 'SUPABASE_SERVICE_ROLE_KEY=secret\n',
      '.env.example': 'NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n',
      'supabase/migrations/1_init.sql': `create table public.profiles (id uuid primary key references auth.users, bio text);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select using (auth.uid() = id);
create policy "update own" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);
create view public.my_profile with (security_invoker = true) as select * from profiles where id = auth.uid();
`,
      'lib/supabase.ts': `export const anonKey = "${supabaseJwt('anon')}";\n`,
      'app/api/account/route.ts': `import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\nexport async function DELETE() {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response(null, { status: 401 });\n  await admin.auth.admin.deleteUser(user.id);\n}\n`,
      'app/api/stripe/webhook/route.ts': `import Stripe from 'stripe';\nexport async function POST(req) {\n  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);\n}\n`,
      'middleware.ts': 'export async function middleware() {\n  await supabase.auth.getUser();\n}\n',
      'components/Post.tsx': "import DOMPurify from 'isomorphic-dompurify';\nexport const P = ({ html }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;\n",
      'firestore.rules': `service cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}\n`,
    },
    { git: true },
  );
  assert.deepEqual(hits(await scan(root)), []);
});

test('globToRegExp follows .gitignore conventions', () => {
  assert.ok(globToRegExp('fixtures/').test('fixtures/a/b.ts'));
  assert.ok(globToRegExp('*.min.js').test('public/vendor/app.min.js'));
  assert.ok(globToRegExp('src/**/*.test.ts').test('src/a/b/c.test.ts'));
  assert.ok(globToRegExp('src/**/*.test.ts').test('src/c.test.ts'));
  assert.ok(!globToRegExp('src/*.ts').test('src/a/b.ts'));
  assert.ok(!globToRegExp('dist').test('distribution/a.js'));
});

test('Supabase: RLS enabled in DO blocks and loops counts; backup SQL is not replayed', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_init.sql': `create table public.a (id int);
create table public.b (id int);
create table public.c (id int);
create table public.d (id int);
do $$ declare t text; begin
  foreach t in array array['a', 'b'] loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;
do $$ begin alter table public.c enable row level security; exception when others then null; end $$;
`,
    'supabase/migrations/2_more.sql': `create table public.e (id int);
create table public.f (id int);
do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname = 'public' loop
    execute format('alter table public.%I enable row level security', r.tablename);
  end loop;
end $$;
create table public.g (id int);
`,
    'docs/backup.sql': 'drop table public.g;\nalter table public.d enable row level security;\n',
  });
  const rls = (await scan(root)).findings.filter((f) => f.ruleId === 'supabase-rls-disabled').map((f) => f.title);
  assert.deepEqual(rls, ['Row Level Security is off for table `g`']);
});

test('Secrets: no alarms for docs, regex literals or PEM headers built at runtime', async () => {
  const key = ['AKIA', 'Q7ZKB2M4XW9RT3NP'].join('');
  const PEM_HEADER = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');
  const root = makeRepo({
    'docs/setup.md': `Export it: AWS_ACCESS_KEY_ID=${key}\n`,
    'scripts/scan.mjs': `const ALLOW = [/${key}/];\n`,
    'scripts/sign.mjs': `const pem = '${PEM_HEADER}\\n' + Buffer.from(der).toString('base64');\n`,
    'server/keys.js': `const pem = "${PEM_HEADER}\\n${'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC'.repeat(2)}\\n${PEM_HEADER.replace('BEGIN', 'END')}";\nconst id = "${key}";\n`,
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.file}:${f.line} ${f.title}`),
    ['server/keys.js:1 Private key committed to the repo', 'server/keys.js:2 AWS access key committed to the repo'],
  );
});

test('Firebase: public storage reads are medium, and titles match the granted access', async () => {
  const root = makeRepo({
    'storage.rules': `service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read;
      allow write: if request.auth.uid != null;
    }
  }
}`,
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.severity} ${f.title}`),
    ['high Any signed-in user can write to your whole Storage bucket', 'medium Anyone can read every file in your Storage bucket'],
  );
});

test('Supabase: partitions without RLS are grouped into one finding per parent', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1.sql': `create table public.events (id int, at date) partition by range (at);
alter table public.events enable row level security;
create table public.events_2027_01 partition of public.events for values from ('2027-01-01') to ('2027-02-01');
create table public.events_2027_02 partition of public.events for values from ('2027-02-01') to ('2027-03-01');
`,
  });
  const titles = (await scan(root)).findings.map((f) => `${f.file}:${f.line} ${f.title}`);
  assert.deepEqual(titles, ['supabase/migrations/1.sql:3 Row Level Security is off for 2 partitions of `events`']);
});

test('Supabase Storage: policies that skip the owner check', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_storage.sql': `insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('documents', 'documents', false);
create policy "Avatars are public" on storage.objects for select using (bucket_id = 'avatars');
create policy "Anyone can upload an avatar" on storage.objects for insert with check (bucket_id = 'avatars');
create policy "Users can delete files" on storage.objects for delete to authenticated using (bucket_id = 'documents');
create policy "Anyone can update avatars" on storage.objects for update using (bucket_id = 'avatars');
create policy "Read documents" on storage.objects for select using (bucket_id = 'documents' and auth.role() = 'authenticated');
create policy "Own documents" on storage.objects for update to authenticated using (bucket_id = 'documents' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "Admins" on storage.objects for delete using (bucket_id = 'documents' and public.is_admin());
create policy "Service" on storage.objects for all to service_role using (true);
create policy "Signed-in uploads" on storage.objects for insert to authenticated with check (bucket_id = 'documents');
`,
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.line} ${f.severity} ${f.title}`),
    [
      '5 high Storage policy lets anyone overwrite any file in the `avatars` bucket',
      '4 medium Storage policy lets any logged-in user delete any file in the `documents` bucket',
      '6 medium Storage policy lets any logged-in user read every file in the private `documents` bucket',
      '3 low Storage policy lets anyone upload files to the `avatars` bucket',
    ],
  );
});

test('Supabase: SECURITY DEFINER functions need a fixed search_path', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_fns.sql': `create or replace function public.has_role(_user_id uuid, _role text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role); -- security definer
$$;
create function public.handle_new_user() returns trigger language plpgsql security definer as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;
create function public.fixed_later() returns void language sql security definer as 'select 1';
create function public.plain() returns void language sql as $$ select 1 $$;
create function public.dropped() returns void language sql security definer as $$ select 1 $$;
`,
    'supabase/migrations/2_fix.sql': `alter function public.fixed_later() set search_path = '';
drop function public.dropped();
create function a() returns void language sql security definer as $$ select 1 $$;
create function b() returns void language sql security definer as $$ select 1 $$;
`,
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.file.split('/').pop()}:${f.line} ${f.severity} ${f.title}`),
    [
      "1_fns.sql:5 low Function `handle_new_user` runs with its owner's privileges but has no fixed search_path",
      "2_fix.sql:3 low 2 functions run with their owner's privileges but have no fixed search_path",
    ],
  );
});

test('Supabase: SECURITY DEFINER functions that take a user ID from the caller', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_fns.sql': `create or replace function public.award_points(p_user_id uuid, amount int)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set points = points + amount where id = p_user_id;
end;
$$;
create function public.get_orders(_user_id uuid) returns setof public.orders
language sql security definer set search_path = public as $$ select * from public.orders where user_id = _user_id $$;
create function public.has_role(_user_id uuid, _role text) returns boolean
language sql stable security definer set search_path = public as $$ select exists (select 1 from public.user_roles where user_id = _user_id and role = _role) $$;
create function public.checked(target_user_id uuid) returns void language plpgsql security definer set search_path = public as $$
begin
  if target_user_id <> auth.uid() then raise exception 'not allowed'; end if;
  delete from public.notes where user_id = target_user_id;
end;
$$;
create function public.backend_only(user_id uuid) returns void language sql security definer set search_path = public as $$ delete from public.notes where notes.user_id = user_id $$;
revoke execute on function public.backend_only(uuid) from public, anon, authenticated;
create function public.members_only(user_id uuid) returns json language sql security definer set search_path = public as $$ select row_to_json(p) from public.profiles p where p.id = user_id $$;
revoke execute on function public.members_only from anon;
create function public.public_only(user_id uuid) returns void language sql security definer set search_path = public as 'insert into public.log (uid) values (user_id)';
revoke all on function public.public_only(uuid) from public;
create function public.invoker(user_id uuid) returns void language sql set search_path = public as $$ delete from public.notes where notes.user_id = user_id $$;
create function public.unused(user_id uuid) returns json language sql security definer set search_path = public as $$ select '{}'::json $$;
create function public.on_signup() returns trigger language plpgsql security definer set search_path = public as $$ begin insert into public.profiles (id) values (new.id); return new; end; $$;
create function public.later(p_user_id uuid) returns setof public.orders language sql security definer set search_path = public as $$ select * from public.orders where user_id = p_user_id $$;
`,
    'supabase/migrations/2_lockdown.sql': `create or replace function public.backend_only(user_id uuid) returns void language sql security definer set search_path = public as $$ delete from public.notes where notes.user_id = user_id $$;
revoke execute on all functions in schema public from anon, authenticated;
grant execute on function public.later(uuid) to authenticated;
`,
  });
  assert.deepEqual(
    (await scan(root)).findings.filter((f) => f.ruleId === 'supabase-rpc-user-param').map((f) => `${f.line} ${f.severity} ${f.title}`),
    ["26 medium Any logged-in user can call `later` with someone else's `p_user_id`"],
  );

  // Before the lockdown migration.
  const before = makeRepo({ 'package.json': supabasePkg, 'supabase/migrations/1_fns.sql': readFileSync(join(root, 'supabase/migrations/1_fns.sql'), 'utf8') });
  assert.deepEqual(
    (await scan(before)).findings.filter((f) => f.ruleId === 'supabase-rpc-user-param').map((f) => `${f.line} ${f.severity} ${f.title}`),
    [
      "1 high Anyone can call `award_points` with someone else's `p_user_id`",
      "21 high Anyone can call `public_only` with someone else's `user_id`",
      "7 medium Anyone can call `get_orders` with someone else's `_user_id`",
      "19 medium Any logged-in user can call `members_only` with someone else's `user_id`",
      "26 medium Anyone can call `later` with someone else's `p_user_id`",
    ],
  );
});

test('Supabase: policies written for the backend should be dropped, not limited to service_role', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1.sql': `create table public.orders (id int, user_id uuid);
alter table public.orders enable row level security;
create policy "System can manage orders" on public.orders for all using (true);
create policy "Anyone can delete" on public.orders for delete using (true);
create policy "Service role can insert orders" on public.orders for insert with check (true);
`,
  });
  const fixes = (await scan(root)).findings.filter((f) => f.ruleId === 'supabase-permissive-policy').map((f) => `${f.line} ${f.fix}`);
  assert.equal(fixes.length, 3);
  assert.match(fixes[0], /^3 This policy looks meant for your backend.*`drop policy "System can manage orders" on public\.orders;`/);
  assert.match(fixes[1], /^4 Replace `true` with an ownership check.*If it's only meant for your backend, drop it instead \(`drop policy "Anyone can delete" on public\.orders;`\)/);
  assert.match(fixes[2], /^5 This policy looks meant for your backend.*`drop policy "Service role can insert orders" on public\.orders;`/);
});

test('.env and public env rules ignore local-only values and commented-out lines', async () => {
  const root = makeRepo(
    {
      '.env': 'DATABASE_URL=postgresql://postgres:password@localhost:5432/app\nNODE_ENV=development\nPORT=3000\n',
      'api/.env': 'DATABASE_URL=postgresql://app:Xk29fLq@db.acme-prod.net:5432/app\n',
      '.env.example': '# VITE_SUPABASE_SERVICE_ROLE_KEY=your-key\n',
    },
    { git: true },
  );
  assert.deepEqual(hits(await scan(root)), ['env-file-committed api/.env']);
});

test('a mature Next.js + Supabase app: auth helpers, signed webhooks, token links, imports (issue #1)', async () => {
  const admin = "import { createAdminClient } from '@/lib/supabase/admin';\n";
  const root = makeRepo({
    'package.json': supabasePkg,
    'lib/supabase/admin.ts': "export function createAdminClient() {\n  return createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n}\n",
    'lib/actor.ts': "export async function getActor() {\n  const { data } = await supabase.auth.getUser();\n  return data.user;\n}\nexport const audit = (x) => log(x);\n",
    'lib/index.ts': "export { getActor } from './actor';\n",
    // 1. Auth in an imported helper (one re-export deep), or an unresolvable one gated by an early return.
    'app/actions/notes.ts': `'use server'\n${admin}import { getActor } from '@/lib'\nexport async function save(x) {\n  await getActor()\n  await createAdminClient().from('notes').insert(x)\n}\n`,
    'app/actions/teams.ts': `'use server';\n${admin}import { loadViewer } from '@acme/session';\nexport async function rename(x) {\n  const { viewer } = await loadViewer();\n  if (!viewer) return { error: 'Sign in' };\n  await createAdminClient().from('teams').update(x);\n}\n`,
    // ...but a helper that isn't an auth check still gets flagged.
    'app/actions/import.ts': `'use server';\n${admin}import { audit } from '@/lib/actor';\nexport async function importRows(x) {\n  const parsed = await parseRows(x);\n  if (!parsed) return;\n  audit(x);\n  await createAdminClient().from('rows').insert(parsed);\n}\n`,
    // 2. A webhook that checks its own HMAC signature.
    'app/api/cal/webhook/route.ts': `${admin}export async function POST(req) {\n  const sig = req.headers.get('x-cal-signature-256');\n  if (hmac(await req.text()) !== sig) return new Response(null, { status: 401 });\n  await createAdminClient().from('bookings').insert({});\n}\n`,
    // 3. An unsubscribe link: the unguessable token is the credential.
    'app/api/unsubscribe/route.ts': `${admin}export async function POST(req) {\n  const token = new URL(req.url).searchParams.get('token');\n  await createAdminClient().from('subscribers').update({ unsubscribed: true }).eq('unsubscribe_token', token);\n}\n`,
    // 4. Stripe's signature check lives in an imported helper (src/ alias).
    'src/lib/stripe.ts': "import Stripe from 'stripe';\nexport function verifyStripeEvent(body, sig) {\n  return stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET);\n}\n",
    'src/app/api/stripe/webhook/route.ts': "import { verifyStripeEvent } from '@/lib/stripe';\nexport async function POST(req) {\n  const event = verifyStripeEvent(await req.text(), req.headers.get('stripe-signature'));\n}\n",
    'src/app/api/stripe/legacy-webhook/route.ts': "import { stripe } from '@/lib/stripe';\nexport async function POST(req) {\n  const event = await req.json();\n}\n",
  });
  assert.deepEqual(hits(await scan(root)), ['stripe-webhook-unverified src/app/api/stripe/legacy-webhook/route.ts', 'unauthenticated-write app/actions/import.ts']);
});

test('Supabase views: revoked grants and caller-filtered views (issue #1)', async () => {
  const root = makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_views.sql': `create view public.open_stats as select count(*) from orders;
create view public.member_names as select id, name from profiles;
revoke select on public.member_names from anon;
create view public.locked as select * from orders;
revoke all on table public.locked from anon, authenticated;
create view public.regranted as select * from orders;
revoke all on public.regranted from anon, authenticated;
grant select on public.regranted to authenticated;
create view public.my_orders as select id, total from orders where user_id = auth.uid();
create view public.team_docs as select d.id, d.title from docs d where is_team_member(d.team_id);
create materialized view public.mv_filtered as select * from orders where user_id = auth.uid();
`,
  });
  const views = (await scan(root)).findings.filter((f) => f.ruleId === 'supabase-view-bypasses-rls');
  assert.deepEqual(
    views.map((f) => [f.line, f.severity, f.title]),
    [
      [1, 'medium', 'View `open_stats` bypasses Row Level Security'],
      [11, 'medium', 'View `mv_filtered` bypasses Row Level Security'],
      [2, 'low', 'Any logged-in user can read every row of view `member_names`'],
      [6, 'low', 'Any logged-in user can read every row of view `regranted`'],
      [9, 'low', "Check that view `my_orders` only returns the caller's rows"],
      [10, 'low', "Check that view `team_docs` only returns the caller's rows"],
    ],
  );
});

test('dangerouslySetInnerHTML: constants and local builders are fine, props are not (issue #1)', async () => {
  const root = makeRepo({
    'components/Theme.tsx': [
      'const THEME_CSS = `:root { --brand: #0af; }`;',
      'function themeScript() {',
      '  return `document.documentElement.dataset.theme = localStorage.theme`;',
      '}',
      'const wrap = (html) => `<div>${html}</div>`;',
      'export const A = () => <style dangerouslySetInnerHTML={{ __html: THEME_CSS }} />;',
      'export const B = () => <script dangerouslySetInnerHTML={{ __html: themeScript() }} />;',
      'export const C = ({ bio }) => <div dangerouslySetInnerHTML={{ __html: wrap(bio) }} />;',
      'export const D = () => { const svg = "<svg></svg>"; return <i dangerouslySetInnerHTML={{ __html: svg }} />; };',
      'export const E = ({ post }) => { const body = post.body; return <i dangerouslySetInnerHTML={{ __html: body }} />; };',
    ].join('\n'),
  });
  assert.deepEqual(
    (await scan(root)).findings.map((f) => `${f.ruleId}:${f.line}`),
    ['xss-unsanitized-html:8', 'xss-unsanitized-html:10'],
  );
});

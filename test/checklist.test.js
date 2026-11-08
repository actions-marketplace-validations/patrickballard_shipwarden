import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../src/scanner.js';
import { toMarkdown, toText } from '../src/report.js';
import { makeRepo } from './helpers.js';

const status = (result) => Object.fromEntries(result.checklist.map((i) => [i.id, i.ok ? 'ok' : i.priority]));

const lovableApp = () =>
  makeRepo({
    'package.json': JSON.stringify({ dependencies: { react: '18.3.1', 'react-router-dom': '6.26.0', '@supabase/supabase-js': '2.45.0' }, devDependencies: { vite: '5.4.0' } }),
    'index.html': '<html><head><title>Lovable App</title><meta property="og:image" content="https://lovable.dev/opengraph-image-p98pqg.png" /></head></html>',
    'src/App.tsx': 'export default () => <Routes><Route path="/" element={<Index />} /><Route path="/login" element={<Login />} /></Routes>;\n',
    'src/pages/Login.tsx': 'await supabase.auth.signInWithPassword({ email, password });\n',
    'supabase/functions/chat/index.ts': "Deno.serve(async (req) => {\n  const r = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', { method: 'POST' });\n});\n",
  });

test('a typical AI-built SPA is missing most launch basics', async () => {
  const result = await scan(lovableApp());
  assert.deepEqual(status(result), {
    'not-found-page': 'must',
    'error-page': 'must',
    'privacy-policy': 'must',
    'password-reset': 'must',
    'ai-rate-limit': 'must',
    'default-branding': 'must',
    'account-deletion': 'should',
    'robots-sitemap': 'should',
    'error-monitoring': 'should',
    'social-preview': 'ok',
  });
  const ai = result.checklist.find((i) => i.id === 'ai-rate-limit');
  assert.equal(`${ai.file}:${ai.line}`, 'supabase/functions/chat/index.ts:2');
  assert.match(result.checklist.find((i) => i.id === 'default-branding').why, /Lovable's default title, description or preview image/);
  assert.match(result.checklist.find((i) => i.id === 'privacy-policy').why, /user accounts/);
  assert.equal(result.findings.length, 0, 'checklist items are never security findings');
});

test('a well-built Next.js app passes every applicable item', async () => {
  const result = await scan(
    makeRepo({
      'package.json': JSON.stringify({ dependencies: { next: '15.0.0', '@supabase/supabase-js': '2.45.0', stripe: '17.0.0', openai: '4.0.0', '@upstash/ratelimit': '2.0.0', '@sentry/nextjs': '8.0.0' } }),
      'app/layout.tsx': "export const metadata = { title: 'Acme', openGraph: { title: 'Acme', images: ['/og.png'] } };\n",
      'app/not-found.tsx': 'export default function NotFound() {}\n',
      'app/error.tsx': "'use client';\nexport default function Error() {}\n",
      'app/(legal)/privacy/page.tsx': 'export default function Privacy() {}\n',
      'app/(legal)/terms/page.tsx': 'export default function Terms() {}\n',
      'app/robots.ts': 'export default function robots() {}\n',
      'app/sitemap.ts': 'export default function sitemap() {}\n',
      'app/login/page.tsx': "'use client';\nawait supabase.auth.signInWithPassword({ email, password });\nawait supabase.auth.resetPasswordForEmail(email);\n",
      'app/settings/actions.ts': "'use server';\nexport async function deleteAccount() {}\n",
      'app/api/chat/route.ts': "import OpenAI from 'openai';\nimport { Ratelimit } from '@upstash/ratelimit';\nexport async function POST() {}\n",
    }),
  );
  assert.ok(result.checklist.length >= 10);
  assert.deepEqual(result.checklist.filter((i) => !i.ok), []);
});

test('Next.js 404 pages under a locale segment or route group count (issue #1)', async () => {
  const pkg = JSON.stringify({ dependencies: { next: '15.0.0' } });
  for (const page of ['app/[locale]/not-found.tsx', 'src/app/(site)/not-found.tsx']) {
    const result = await scan(makeRepo({ 'package.json': pkg, [page]: 'export default function NotFound() {}\n' }));
    assert.equal(result.checklist.find((i) => i.id === 'not-found-page').ok, true, page);
  }
});

test('libraries and CLIs get no checklist; opt-outs work', async () => {
  const lib = await scan(makeRepo({ 'package.json': JSON.stringify({ name: 'some-lib', dependencies: { zod: '3.0.0' } }), 'src/index.js': 'export const x = 1;\n' }));
  assert.deepEqual(lib.checklist, []);

  const root = lovableApp();
  const skipped = await scan(root, { skipChecks: ['robots-sitemap'] });
  assert.ok(!skipped.checklist.some((i) => i.id === 'robots-sitemap'));
  assert.deepEqual((await scan(root, { checklist: false })).checklist, []);

  const viaFile = makeRepo({ '.shipwardenignore': 'check:error-monitoring\ncheck:account-deletion\n', 'package.json': JSON.stringify({ dependencies: { next: '15.0.0', 'next-auth': '5.0.0' } }) });
  const ids = (await scan(viaFile)).checklist.map((i) => i.id);
  assert.ok(ids.includes('not-found-page'));
  assert.ok(!ids.includes('error-monitoring') && !ids.includes('account-deletion'));
});

test('checklist shows in text and markdown reports', async () => {
  const result = await scan(lovableApp());
  const text = toText(result);
  assert.match(text, /Launch checklist · 1 of 10 done · 6 must-haves missing/);
  assert.match(text, /MUST HAVE {2}No privacy policy/);
  assert.match(text, /✔ Done: Social preview image/);

  const md = toMarkdown(result);
  assert.match(md, /no security issues found/);
  assert.match(md, /<details open><summary>📋 <b>Launch checklist<\/b>: 1 of 10 done · 6 must-haves missing<\/summary>/);
  assert.match(md, /- ❌ \*\*No rate limit on paid AI calls\*\* · must have \(`supabase\/functions\/chat\/index\.ts:2`\)/);
});

test('an admin-only login does not count as user accounts', async () => {
  const result = await scan(
    makeRepo({
      'package.json': JSON.stringify({ dependencies: { react: '18.3.1', '@supabase/supabase-js': '2.45.0' }, devDependencies: { vite: '5.4.0' } }),
      'src/routes/admin.tsx': 'await supabase.auth.signInWithPassword({ email, password });\n',
    }),
  );
  const ids = result.checklist.map((i) => i.id);
  assert.ok(!ids.includes('password-reset') && !ids.includes('privacy-policy') && !ids.includes('account-deletion'));
});

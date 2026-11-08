import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { judgeFindings } from '../src/ai-judge.js';
import { MARKER, toAnnotations, toMarkdown } from '../src/report.js';
import { makeRepo, supabasePkg } from './helpers.js';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

const finding = (overrides) => ({
  ruleId: 'unauthenticated-write',
  severity: 'medium',
  confidence: 'medium',
  title: 'Endpoint changes data',
  file: 'app/actions.ts',
  line: 3,
  message: 'msg',
  fix: 'fix',
  ...overrides,
});

function fakeClient(response) {
  const calls = [];
  return { calls, beta: { messages: { create: async (params) => (calls.push(params), response) } } };
}

test('AI judge drops false positives among uncertain findings only', async () => {
  const sure = finding({ ruleId: 'supabase-rls-disabled', severity: 'critical', confidence: 'high', file: 'a.sql' });
  const fp = finding({ file: 'app/a.ts' });
  const real = finding({ file: 'app/b.ts' });
  const client = fakeClient({
    stop_reason: 'end_turn',
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          verdicts: [
            { id: 1, verdict: 'false_positive', reason: 'auth checked by requireOwner()', fix: '' },
            { id: 2, verdict: 'real', reason: 'no check at all', fix: 'call getUser()' },
          ],
        }),
      },
    ],
  });
  const fileContents = new Map([
    ['app/a.ts', 'a\nb\nc'],
    ['app/b.ts', 'x'],
    ['middleware.ts', 'export function middleware() {}'],
  ]);
  const out = await judgeFindings([sure, fp, real], { client, fileContents });

  assert.equal(out.judged, 2);
  assert.equal(out.dismissed, 1);
  assert.deepEqual(out.findings.map((f) => f.file), ['a.sql', 'app/b.ts']);
  assert.deepEqual(out.findings[1].ai, { verdict: 'real', reason: 'no check at all', fix: 'call getUser()' });
  assert.equal(out.findings[1].confidence, 'high');

  const [params] = client.calls;
  assert.equal(params.model, 'claude-opus-5-5');
  assert.equal(params.fallbacks, 'default');
  assert.deepEqual(params.betas, ['server-side-fallback-2026-07-01']);
  assert.equal(params.output_config.format.type, 'json_schema');
  const prompt = params.messages[0].content;
  assert.match(prompt, /<finding id="1">[\s\S]*app\/a\.ts:3/);
  assert.match(prompt, /1 \| a\n2 \| b\n3 \| c/);
  assert.match(prompt, /<supporting_file path="middleware.ts"/);
  assert.doesNotMatch(prompt, /a\.sql/);
});

test('AI judge leaves findings untouched on refusal or nothing to judge', async () => {
  const f = finding();
  const refused = await judgeFindings([f], { client: fakeClient({ stop_reason: 'refusal', content: [] }), fileContents: new Map() });
  assert.deepEqual(refused.findings, [f]);
  assert.match(refused.error, /declined/);

  const client = fakeClient({});
  const none = await judgeFindings([{ ...f, confidence: 'high' }], { client, fileContents: new Map() });
  assert.equal(client.calls.length, 0);
  assert.equal(none.judged, 0);
});

test('markdown report and annotations', () => {
  const result = {
    filesScanned: 12,
    stack: ['Next.js', 'Supabase'],
    findings: [finding({ severity: 'critical', title: 'RLS is off for `profiles`', message: 'line1\nline2', fix: 'a | b' })],
  };
  const md = toMarkdown(result, { link: (file, line) => `https://x/${file}#L${line}`, scopeNote: 'the 2 files changed in this PR' });
  assert.ok(md.startsWith(MARKER));
  assert.match(md, /ShipWarden found 1 security issue\b/);
  assert.match(md, /\| 🔴 \| RLS is off for `profiles` \| \[`app\/actions\.ts:3`\]\(https:\/\/x\/app\/actions\.ts#L3\) \|/);
  assert.match(md, /<b>RLS is off for <code>profiles<\/code><\/b>/);
  assert.match(md, /Scanned 12 files · reporting on the 2 files changed in this PR · Next.js, Supabase/);
  assert.match(toMarkdown({ ...result, findings: [] }), /no security issues found/);

  const [annotation] = toAnnotations(result.findings);
  assert.equal(annotation.split('::').length, 3, 'message must not contain raw "::" separators from properties');
  assert.match(annotation, /^::error file=app\/actions\.ts,line=3,title=ShipWarden%3A RLS is off for profiles::line1%0Aline2%0A%0AFix: a \| b$/);
});

function run(script, args, env) {
  return new Promise((resolve) => {
    execFile(process.execPath, [path.join(SRC, script), ...args], { env: { PATH: process.env.PATH, ...env } }, (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
  });
}

const vulnerableRepo = () =>
  makeRepo({
    'package.json': supabasePkg,
    'supabase/migrations/1_init.sql': 'create table public.profiles (id uuid);\n',
    'supabase/migrations/2_old.sql': 'create table public.old (id uuid);\n',
    'components/Bio.tsx': 'export const B = ({ u }) => <div dangerouslySetInnerHTML={{ __html: u.bio }} />;\n',
  });

test('CLI prints JSON and exits 1 on critical findings', async () => {
  const { code, stdout } = await run('cli.js', [vulnerableRepo(), '--format', 'json']);
  assert.equal(code, 1);
  const json = JSON.parse(stdout);
  assert.equal(json.findings.length, 3);
  assert.equal(json.fileContents, undefined);

  const quiet = await run('cli.js', [vulnerableRepo(), '--fail-on', 'none', '--no-color']);
  assert.equal(quiet.code, 0);
  assert.match(quiet.stdout, / CRITICAL  Row Level Security is off for table profiles/);
});

test('GitHub Action on a pull request: scopes to changed files, annotates, comments, fails', async () => {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, body: body && JSON.parse(body), auth: req.headers.authorization });
      res.setHeader('content-type', 'application/json');
      if (req.url.startsWith('/repos/acme/app/pulls/7/files')) {
        return res.end(JSON.stringify([{ filename: 'supabase/migrations/1_init.sql', status: 'added' }, { filename: 'components/Bio.tsx', status: 'modified' }]));
      }
      if (req.method === 'GET' && req.url.startsWith('/repos/acme/app/issues/7/comments')) return res.end('[]');
      res.statusCode = 201;
      res.end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shipwarden-gh-'));
  const files = { event: path.join(tmp, 'event.json'), summary: path.join(tmp, 'summary.md'), output: path.join(tmp, 'output.txt') };
  fs.writeFileSync(files.event, JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc123' } } }));

  const { code, stdout } = await run('action.js', [], {
    GITHUB_WORKSPACE: vulnerableRepo(),
    GITHUB_EVENT_PATH: files.event,
    GITHUB_STEP_SUMMARY: files.summary,
    GITHUB_OUTPUT: files.output,
    GITHUB_REPOSITORY: 'acme/app',
    GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`,
    INPUT_GITHUB_TOKEN: 'test-token',
  });
  server.close();

  assert.equal(code, 1);
  assert.match(stdout, /^::error file=supabase\/migrations\/1_init\.sql,line=1,/m);
  assert.match(stdout, /^::warning file=components\/Bio\.tsx,line=1,/m);
  assert.doesNotMatch(stdout, /2_old\.sql/, 'unchanged files are out of scope');

  const post = requests.find((r) => r.method === 'POST');
  assert.equal(post.url, '/repos/acme/app/issues/7/comments');
  assert.equal(post.auth, 'Bearer test-token');
  assert.match(post.body.body, /ShipWarden found 2 security issues/);
  assert.match(post.body.body, /https:\/\/github\.com\/acme\/app\/blob\/abc123\/supabase\/migrations\/1_init\.sql#L1/);
  assert.match(fs.readFileSync(files.summary, 'utf8'), /ShipWarden found 2 security issues/);
  assert.equal(fs.readFileSync(files.output, 'utf8'), 'findings=2\ncritical=1\nhigh=0\n');
});

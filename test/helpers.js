import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export function makeRepo(files, { git = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipwarden-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  if (git) execFileSync('git', ['init', '-q', dir]);
  return dir;
}

/** "ruleId file" pairs, for order-independent assertions. */
export const hits = (result) => result.findings.map((f) => `${f.ruleId} ${f.file}`).sort();

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

// Assembled at runtime so the repo never contains secret-shaped strings.
export const supabaseJwt = (role) =>
  ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', b64({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role, iat: 1700000000, exp: 2000000000 }), 'c2lnbmF0dXJlLW5vdC1yZWFsLWJ1dC1sb25n'].join('.');
export const stripeLiveKey = ['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3'].join('_');
export const browserFlag = ['dangerously', 'AllowBrowser: true'].join('');

export const supabasePkg = JSON.stringify({ dependencies: { next: '15.0.0', '@supabase/supabase-js': '2.45.0', stripe: '17.0.0', '@prisma/client': '6.0.0' } });
export const vitePkg = JSON.stringify({ dependencies: { react: '18.3.1', '@supabase/supabase-js': '2.45.0', openai: '4.0.0' }, devDependencies: { vite: '5.4.0' } });

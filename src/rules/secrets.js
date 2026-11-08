import { isClientCode, lineAt, looksLikePlaceholder, makeFinding } from '../util.js';

const ROTATE = 'Removing it from the code is not enough: it stays in git history and in any build you already deployed.';

const PATTERNS = [
  { name: 'Stripe live secret key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, severity: 'critical', where: 'the Stripe dashboard (Developers → API keys)' },
  { name: 'OpenAI API key', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{30,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, severity: 'critical', where: 'platform.openai.com → API keys' },
  { name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}/g, severity: 'critical', where: 'the Claude Console → API keys' },
  { name: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, severity: 'critical', where: 'Supabase → Project Settings → API Keys' },
  { name: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'high', where: 'the AWS IAM console' },
  { name: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g, severity: 'high', where: 'GitHub → Settings → Developer settings' },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, severity: 'high', where: 'your Slack app settings' },
  { name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: 'high', where: 'SendGrid → Settings → API Keys' },
  // Header plus an actual key body (also as an escaped "\\n" in JSON), not code that builds a PEM at runtime.
  { name: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\s|\\n)*[A-Za-z0-9+/=]{40,}/g, severity: 'critical', where: 'wherever it was issued' },
];

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function jwtPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export const serviceRoleKey = {
  id: 'supabase-service-role-key',
  title: 'Supabase service_role key is in the code',
  severity: 'critical',
  check(file, ctx) {
    const findings = [];
    for (const m of file.content.matchAll(JWT)) {
      if (jwtPayload(m[0])?.role !== 'service_role') continue;
      const inBrowser = isClientCode(file, ctx);
      findings.push(
        makeFinding(this, file.path, lineAt(file.content, m.index), {
          message:
            'This is your Supabase `service_role` key. It skips every Row Level Security rule, so anyone who gets it can read, change or delete everything in your database' +
            (inBrowser ? ', and this file is shipped to every visitor\'s browser.' : '.'),
          fix: `Rotate the key now in Supabase (Project Settings → API Keys), delete it from the code, and only use it in server code through an environment variable with no NEXT_PUBLIC_/VITE_ prefix. ${ROTATE}`,
        }),
      );
    }
    return findings;
  },
};

export const hardcodedSecret = {
  id: 'hardcoded-secret',
  title: 'Secret key committed to the repo',
  severity: 'critical',
  check(file) {
    // Docs are full of illustrative keys; a real one there is rare enough to accept missing.
    if (/\.md$|(^|\/)docs?\//i.test(file.path)) return [];
    const findings = [];
    for (const p of PATTERNS) {
      for (const m of file.content.matchAll(p.re)) {
        // Skip placeholders and regex literals such as a secret scanner's own patterns.
        if (looksLikePlaceholder(m[0]) || file.content[m.index - 1] === '/') continue;
        findings.push(
          makeFinding(this, file.path, lineAt(file.content, m.index), {
            severity: p.severity,
            title: `${p.name[0].toUpperCase()}${p.name.slice(1)} committed to the repo`,
            message: `A ${p.name} is written directly in this file. Anyone who can see the repo, or your shipped JavaScript if this runs in the browser, can use it on your account.`,
            fix: `Revoke it in ${p.where}, then load the new one from a server-side environment variable. ${ROTATE}`,
          }),
        );
      }
    }
    return findings;
  },
};

const PUBLIC_VAR = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)([A-Z0-9_]+)/g;
const CRITICAL_NAME = /SERVICE_ROLE|(^|_)SECRET(_|$)|PRIVATE_KEY|DATABASE_URL$|DB_URL$|POSTGRES_URL$|PASSWORD$/;
const AI_KEY_NAME = /(^|_)(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|REPLICATE|ELEVENLABS|RESEND|SENDGRID|TWILIO|DEEPSEEK|PERPLEXITY|OPENROUTER|XAI|TOGETHER|FAL|COHERE|HUGGINGFACE|HF)_(API_)?(KEY|TOKEN)$/;

export const publicEnvSecret = {
  id: 'public-env-secret',
  title: 'Secret exposed through a public env variable',
  severity: 'critical',
  check(file) {
    const findings = [];
    const seen = new Set();
    for (const m of file.content.matchAll(PUBLIC_VAR)) {
      const [name, prefix, rest] = m;
      if (seen.has(name) || /PUBLISHABLE|ANON/.test(rest)) continue;
      const lineStart = file.content.lastIndexOf('\n', m.index) + 1;
      if (/^\s*(#|\/\/|\*)/.test(file.content.slice(lineStart, m.index))) continue; // commented out
      const critical = CRITICAL_NAME.test(rest);
      if (!critical && !AI_KEY_NAME.test(rest)) continue;
      // The ai-key-in-browser finding already covers an AI key used from browser code.
      if (!critical && /dangerouslyAllowBrowser\s*:\s*true/.test(file.content)) continue;
      seen.add(name);
      findings.push(
        makeFinding(this, file.path, lineAt(file.content, m.index), {
          severity: critical ? 'critical' : 'high',
          title: `\`${name}\` is exposed to the browser`,
          message: `Variables starting with \`${prefix}\` are copied into your frontend JavaScript at build time, so anyone can open dev tools and read \`${name}\`.`,
          fix: `Rename it without the \`${prefix}\` prefix and only use it in server code (API routes, server actions, edge functions). Then rotate the value, because every deployed build already contains it.`,
        }),
      );
    }
    return findings;
  },
};

export const aiKeyInBrowser = {
  id: 'ai-key-in-browser',
  title: 'AI API key is sent to the browser',
  severity: 'high',
  message:
    'The AI client is created with `dangerouslyAllowBrowser` switched on, so your API key ships to every visitor. Anyone can copy it and run up your bill.',
  fix: 'Move the AI call into a server route, server action or edge function, and call that from the browser instead.',
  check(file) {
    const m = /dangerouslyAllowBrowser\s*:\s*true/.exec(file.content);
    return m ? [makeFinding(this, file.path, lineAt(file.content, m.index))] : [];
  },
};

export default [serviceRoleKey, hardcodedSecret, publicEnvSecret, aiKeyInBrowser];

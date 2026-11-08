import { EDGE_FUNCTION, ROUTE_HANDLER, hasDirective, importedHelpers, isServerEndpoint, lineAt, looksLikePlaceholder, makeFinding } from '../util.js';

const MUTATING_EXPORT = /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=|\bas\s+(POST|PUT|PATCH|DELETE)\b/;

const AUTH_CHECK = new RegExp(
  [
    String.raw`\b(?:getUser|getClaims|getSession|getServerSession|getServerAuthSession|currentUser|getAuth|verifyIdToken|verifySessionCookie|validateRequest|getToken|getKindeServerSession|jwtVerify|constructEvent|constructEventAsync|verifyWebhook|timingSafeEqual|verifyOtp|exchangeCodeForSession)\s*\(`,
    String.raw`\b(?:require|check|ensure|assert|verify|validate|with|is)(?:Auth|Authenticated|User|Admin|Session|Signature)\w*\s*\(`,
    String.raw`\bauth\s*\(\s*\)`,
    String.raw`\.protect\s*\(`,
    String.raw`\bjwt\.verify\s*\(`,
    String.raw`(?:===|!==)\s*(?:process\.env|Deno\.env\.get)\b`,
    String.raw`[!=]==\s*\x60Bearer\s`,
    // x-cal-signature-256, stripe-signature, svix-signature, x-hub-signature-256, x-cron-secret...
    String.raw`headers(?:\.get\(\s*|\[\s*)['"](?:x-[\w-]*(?:secret|token|key)|[\w-]*signature[\w-]*)['"]\s*[)\]]`,
    String.raw`\.rpc\(\s*['"](?:has_role|is_admin|has_permission|check_\w+)['"]`,
  ].join('|'),
  'i',
);
const GUARD_NAME = /auth|guard|verif|require|protect|permission|assert|ensure|check/i;
const CLIENT_FACTORY = /client$|^(create|get|new|init|make)\w*(client|supabase|stripe|db)/i;

const IDENTITY = /user|actor|session|auth|member|tenant|account|principal|viewer|claims|role|permission|allowed|authori[sz]|access/i;
const EARLY_EXIT = /const\s+(?:([\w$]+)|\{([^}]*)\})\s*=\s*await\s+([\w$]+)\s*\([^\n]*\n(?:\s*\n)?\s*if\s*\(\s*!\s*([\w$]+)(?:\??\.([\w$]+))?[^)\n]*\)\s*\{?\s*(?:return|throw|redirect\s*\(|notFound\s*\(|unauthorized\s*\(|forbidden\s*\()/g;

/** `const gate = await requireActor(); if (!gate.actor) return ...`: a helper whose result gates the rest. */
function exitsWithoutCaller(code) {
  for (const m of code.matchAll(EARLY_EXIT)) {
    const [, single, destructured, fn, checked, prop] = m;
    const declared = single ? [single] : destructured.split(',').map((p) => p.split(':').pop().trim());
    if (!declared.includes(checked) || CLIENT_FACTORY.test(fn)) continue;
    if (IDENTITY.test(fn) || IDENTITY.test(prop ?? checked)) return true;
  }
  return false;
}

// Email-confirm and unsubscribe links: the unguessable token in the URL is the credential.
const TOKEN_INPUT = /\.get\(\s*['"]\w*token['"]\s*\)|\b(?:searchParams|params|query|body)\??\.\w*token\b|\{[^}]*\b\w*token\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request|params|searchParams|body|context|props)\b/i;
const TOKEN_LOOKUP = /\.(?:eq|match)\(\s*\{?\s*['"]?\w*token\w*['"]?\s*[,:]|where\s*:\s*\{[^}]*\b\w*token\w*\s*[:,}]|\b(?:verify|consume|validate|check|find)\w*Token\s*\(/i;

/** Calls an auth helper it imports or defines, e.g. `await authorize(req)` from ../_shared/authorize.ts. */
function callsGuardHelper(code) {
  const names = new Set();
  for (const m of code.matchAll(/import\s*\{([^}]*)\}\s*from/g)) {
    for (const part of m[1].split(',')) names.add(part.trim().split(/\s+as\s+/).pop());
  }
  for (const m of code.matchAll(/import\s+(\w+)\s*(?:,|from)/g)) names.add(m[1]);
  for (const m of code.matchAll(/(?:function\s+|const\s+)(\w+)\s*(?:=\s*(?:async\s*)?\(|\()/g)) names.add(m[1]);
  return [...names].some((n) => n && GUARD_NAME.test(n) && !CLIENT_FACTORY.test(n) && new RegExp(String.raw`\b${n}\s*\(`).test(code.replace(/import[^;]*;/g, '')));
}

const ADMIN_CLIENT = /service[_-]?role|supabaseAdmin|createAdminClient|createServiceClient|createServiceRoleClient|adminClient|SUPABASE_SECRET_KEY|\.auth\.admin\./i;
const SUPABASE_WRITE = /\.from\(\s*['"`][^'"`]+['"`]\s*\)\s*\.(insert|update|upsert|delete)\s*\(|\.auth\.admin\.(deleteUser|updateUserById|createUser|inviteUserByEmail)\s*\(/;
const ORM_WRITE = /\bprisma\.\w+\.(create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(|\bdb\.(insert|update|delete)\s*\(|\.(insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|findOneAndUpdate|findOneAndDelete|findByIdAndUpdate|findByIdAndDelete)\s*\(|\bsql`\s*(insert|update|delete)\b/i;

function endpointLabel(file) {
  if (EDGE_FUNCTION.test(file.path)) return 'Supabase Edge Function';
  if (ROUTE_HANDLER.test(file.path) || /pages\/api\//.test(file.path)) return 'API route';
  return "server action (every exported function in a 'use server' file is a public endpoint anyone can call)";
}

export const unauthenticatedWrite = {
  id: 'unauthenticated-write',
  title: 'Endpoint changes data without checking who is calling',
  severity: 'medium',
  confidence: 'medium',
  check(file, ctx) {
    if (!isServerEndpoint(file)) return [];
    const c = file.content;
    if (ROUTE_HANDLER.test(file.path) && !MUTATING_EXPORT.test(c)) return [];
    if (AUTH_CHECK.test(c) || callsGuardHelper(c) || exitsWithoutCaller(c) || (TOKEN_INPUT.test(c) && TOKEN_LOOKUP.test(c))) return [];
    // The check lives in a helper this file imports, e.g. requireActor() in lib/auth.ts.
    if (importedHelpers(file, ctx).some((h) => !CLIENT_FACTORY.test(h.name) && AUTH_CHECK.test(h.source))) return [];

    // A plain Supabase client is still protected by RLS; the admin client is not.
    const admin = ADMIN_CLIENT.test(c);
    const m = (admin && SUPABASE_WRITE.exec(c)) || ORM_WRITE.exec(c);
    if (!m) return [];
    const viaAdmin = admin && SUPABASE_WRITE.test(m[0]);
    const call = `${m[0].replace(/\s+/g, '').replace(/^\./, '')}${m[0].trim().endsWith('(') ? ')' : ''}`;
    return [
      makeFinding(this, file.path, lineAt(c, m.index), {
        severity: viaAdmin ? 'high' : 'medium',
        message:
          `This ${endpointLabel(file)} writes to the database (\`${call}\`) but never checks who the caller is. ` +
          (viaAdmin
            ? 'It uses the Supabase admin/service-role client, which skips RLS, so anyone who finds the URL can change or delete any data.'
            : 'Direct database clients skip Supabase RLS, so anyone who finds the URL can make this change.'),
        fix:
          'Check the user at the top of the handler and confirm they own the data before writing. For example: ' +
          "`const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('Unauthorized', { status: 401 })` " +
          'If auth is enforced elsewhere (middleware, a wrapper), add a `shipwarden-ignore` comment above this line.',
      }),
    ];
  },
};

const STRIPE_IMPORT = /import[^;]*['"][^'"]*\bstripe\b[^'"]*['"]|require\(\s*['"]stripe['"]\s*\)|new\s+Stripe\s*\(/;

export const stripeWebhook = {
  id: 'stripe-webhook-unverified',
  title: 'Stripe webhook does not verify the signature',
  severity: 'high',
  message:
    "This Stripe webhook handler never checks the `Stripe-Signature` header, so anyone can send it a fake \"payment succeeded\" event and unlock paid features for free.",
  fix: "Verify every event: `const event = stripe.webhooks.constructEvent(rawBody, req.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET)` (use `constructEventAsync` on Edge/Deno).",
  check(file, ctx) {
    if (!/webhook/i.test(file.path) || !/\.[cm]?[jt]sx?$/.test(file.path)) return [];
    const c = file.content;
    if (!STRIPE_IMPORT.test(c) || /constructEvent/.test(c)) return [];
    if (importedHelpers(file, ctx).some((h) => /constructEvent/.test(h.source))) return [];
    const handler = /export\s+(?:async\s+)?function\s+POST\b|export\s+const\s+POST\b|export\s+default|\bserve\s*\(|Deno\.serve\s*\(/.exec(c);
    return [makeFinding(this, file.path, handler ? lineAt(c, handler.index) : 1)];
  },
};

export const getSessionOnServer = {
  id: 'supabase-getsession-on-server',
  title: 'Server trusts `getSession()` for auth',
  severity: 'medium',
  confidence: 'medium',
  message:
    "`supabase.auth.getSession()` reads the session from cookies without verifying it, so on the server a user can forge it. Supabase's docs say never to trust it in server code.",
  fix: 'Use `supabase.auth.getUser()` (or `getClaims()`) for any auth decision on the server.',
  check(file, ctx) {
    if (!ctx.usesSupabase) return [];
    const isServer =
      isServerEndpoint(file) ||
      /(^|\/)middleware\.[jt]s$/.test(file.path) ||
      (/(^|\/)app\/(?:.*\/)?(page|layout)\.[jt]sx?$/.test(file.path) && !hasDirective(file.content, 'use client'));
    if (!isServer || /\.auth\.(getUser|getClaims)\s*\(/.test(file.content)) return [];
    const m = /\.auth\.getSession\s*\(/.exec(file.content);
    return m ? [makeFinding(this, file.path, lineAt(file.content, m.index))] : [];
  },
};

const LITERAL = /^(?:(['"`])(?:(?!\1)[^$\\]|\\.|\$(?!\{))*\1|-?\d[\d.]*|true|false|null|undefined)$/;

/**
 * Values that can't carry user input: a module-level constant, a constant string, or a function
 * defined in this file called with only literal arguments (e.g. a CSS or JSON-LD builder).
 */
function isConstant(content, expr) {
  const ref = /^([\w$]+)(?:\.[\w$]+)*$/.exec(expr);
  if (ref) {
    const name = ref[1].replace(/\$/g, '\\$');
    if (new RegExp(String.raw`^(?:export\s+)?const\s+${name}\s*(?::[^=\n]+)?=`, 'm').test(content)) return true;
    const local = new RegExp(String.raw`\bconst\s+${name}\s*(?::[^=\n]+)?=\s*([^;\n]+)`).exec(content);
    return !!local && LITERAL.test(local[1].trim());
  }
  const call = /^([\w$]+)\(([^()]*)\)$/.exec(expr);
  if (!call) return false;
  const name = call[1].replace(/\$/g, '\\$');
  const defined = new RegExp(String.raw`\bfunction\s+${name}\s*\(|\bconst\s+${name}\s*=\s*(?:async\s*)?(?:\([^)]*\)|[\w$]+)\s*=>`).test(content);
  const args = call[2].trim() ? call[2].split(',').map((a) => a.trim()) : [];
  return defined && args.every((a) => LITERAL.test(a) || new RegExp(String.raw`^(?:export\s+)?const\s+${a.replace(/\$/g, '\\$')}\s*[:=]`, 'm').test(content));
}

const SANITIZER = /DOMPurify|dompurify|sanitize-html|sanitizeHtml|isomorphic-dompurify|rehype-sanitize|\bxss\(/;

export const unsafeHtml = {
  id: 'xss-unsanitized-html',
  title: 'Unsanitized HTML rendered with dangerouslySetInnerHTML',
  severity: 'medium',
  confidence: 'medium',
  check(file) {
    if (!/\.[jt]sx$/.test(file.path) || SANITIZER.test(file.content)) return [];
    const findings = [];
    for (const m of file.content.matchAll(/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]*?)\s*\}\}/g)) {
      const expr = m[1];
      if (/^(['"`])[^$]*\1$/.test(expr) || /JSON\.stringify|sanitiz|purify|escape/i.test(expr) || isConstant(file.content, expr)) continue;
      findings.push(
        makeFinding(this, file.path, lineAt(file.content, m.index), {
          message: `\`${expr}\` is inserted as raw HTML. If any part of it comes from users (or from an AI model), an attacker can run JavaScript in other users' browsers and steal their sessions.`,
          fix: 'Render it as text, or sanitize first: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`.',
        }),
      );
    }
    return findings;
  },
};

const RAW_SQL = [
  /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*`[^`]*\$\{/g,
  /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*(['"])(?:(?!\1)[^\n])*\1\s*\+/g,
  /\.(?:query|execute)\s*\(\s*`[^`]*\b(?:select|insert|update|delete)\b[^`]*\$\{/gi,
  /\.(?:query|execute)\s*\(\s*(['"])(?:(?!\1)[^\n])*\b(?:select|insert|update|delete)\b(?:(?!\1)[^\n])*\1\s*\+/gi,
  /\b(?:knex|db|sql)\.raw\s*\(\s*`[^`]*\$\{/g,
];

export const sqlInjection = {
  id: 'sql-injection',
  title: 'SQL query built from string interpolation',
  severity: 'high',
  confidence: 'medium',
  message: 'This query is built by pasting values into the SQL text. If any value comes from the request, an attacker can rewrite the query and read or delete your data.',
  fix: "Pass values as parameters instead: Prisma's `$queryRaw` tagged template, `db.query('select ... where id = $1', [id])`, or your ORM's query builder.",
  check(file) {
    if (!/\.[cm]?[jt]sx?$/.test(file.path)) return [];
    const seen = new Set();
    const findings = [];
    for (const re of RAW_SQL) {
      for (const m of file.content.matchAll(re)) {
        const line = lineAt(file.content, m.index);
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push(makeFinding(this, file.path, line));
      }
    }
    return findings;
  },
};

const ENV_FILE = /(^|\/)\.env(\.[\w.-]+)?$/;
const ENV_TEMPLATE = /\.(example|sample|template|defaults|dist|schema)$/i;
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)/;

export const committedEnvFile = {
  id: 'env-file-committed',
  title: '.env file with secrets is committed',
  severity: 'high',
  check(file, ctx) {
    if (!ctx.tracked || !ENV_FILE.test(file.path) || ENV_TEMPLATE.test(file.path)) return [];
    const vars = [...file.content.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"#][^\n'"]*)/gm)];
    // Public values and local-only dev settings (localhost databases, "password") aren't leaks.
    const secrets = vars
      .filter(([, name, value]) => !PUBLIC_PREFIX.test(name) && !/localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal/.test(value) && !looksLikePlaceholder(value) && !/^(password|secret|changeme|true|false|\d+|development|production|test)$/i.test(value))
      .map(([, name]) => name);
    if (!secrets.length) return [];
    const shown = secrets.slice(0, 5).map((n) => `\`${n}\``).join(', ');
    return [
      makeFinding(this, file.path, 1, {
        message: `This file is in git, so everyone with access to the repo can read ${shown}${secrets.length > 5 ? ` and ${secrets.length - 5} more` : ''}.`,
        fix: `Add \`${file.path.split('/').pop()}\` to .gitignore, run \`git rm --cached ${file.path}\`, and rotate every value in it. They stay in git history even after you delete the file.`,
      }),
    ];
  },
};

export default [unauthenticatedWrite, stripeWebhook, getSessionOnServer, unsafeHtml, sqlInjection, committedEnvFile];

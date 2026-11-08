#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from './scanner.js';
import { DEFAULT_MODEL, judgeFindings } from './ai-judge.js';
import { toJson, toMarkdown, toText } from './report.js';
import { SEVERITIES, atLeast } from './util.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8'));

const HELP = `ShipWarden ${version} · security checks for apps built with Lovable, Bolt, Cursor, v0 & co.

Usage: shipwarden [path] [options]

Options:
  --format <text|json|markdown>  Output format (default: text)
  --fail-on <severity|none>      Exit 1 if any finding is at least this severe (default: critical)
  --ignore <glob>                Skip matching files (repeatable; also reads .shipwardenignore)
  --ai                           Ask Claude to double-check uncertain findings (needs ANTHROPIC_API_KEY)
  --model <id>                   Claude model for --ai (default: ${DEFAULT_MODEL})
  --no-color                     Disable colors
  -v, --version                  Print version
  -h, --help                     Show this help

Severities: ${SEVERITIES.join(', ')}
`;

function parseArgs(argv) {
  const opts = { target: '.', format: 'text', failOn: 'critical', ignore: [], ai: false, model: DEFAULT_MODEL, color: process.stdout.isTTY && !process.env.NO_COLOR };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value`);
      return v;
    };
    if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '-v' || arg === '--version') opts.version = true;
    else if (arg === '--format') opts.format = value();
    else if (arg === '--json') opts.format = 'json';
    else if (arg === '--fail-on') opts.failOn = value();
    else if (arg === '--ignore') opts.ignore.push(value());
    else if (arg === '--ai') opts.ai = true;
    else if (arg === '--model') opts.model = value();
    else if (arg === '--no-color') opts.color = false;
    else if (arg.startsWith('-')) throw new Error(`Unknown option ${arg}`);
    else opts.target = arg;
  }
  if (!['text', 'json', 'markdown'].includes(opts.format)) throw new Error(`Unknown format "${opts.format}"`);
  if (opts.failOn !== 'none' && !SEVERITIES.includes(opts.failOn)) throw new Error(`Unknown severity "${opts.failOn}"`);
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) return void process.stdout.write(HELP);
  if (opts.version) return void console.log(version);

  const root = path.resolve(opts.target);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`Not a directory: ${opts.target}`);
  const result = await scan(root, { ignore: opts.ignore });

  let aiNote = '';
  let ai;
  if (opts.ai) {
    ai = await judgeFindings(result.findings, { model: opts.model, fileContents: result.fileContents });
    if (ai.error) console.error(`AI review skipped: ${ai.error}.`);
    result.findings = ai.findings;
    if (ai.judged) aiNote = `AI reviewed ${ai.judged} uncertain finding(s), dismissed ${ai.dismissed}`;
  }

  if (opts.format === 'json') process.stdout.write(`${toJson(result, ai ? { ai: { judged: ai.judged, dismissed: ai.dismissed } } : {})}\n`);
  else if (opts.format === 'markdown') process.stdout.write(`${toMarkdown(result, { aiNote })}\n`);
  else process.stdout.write(toText(result, { color: opts.color, aiNote }));

  if (result.findings.some((f) => atLeast(f.severity, opts.failOn))) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`shipwarden: ${error.message}`);
  process.exitCode = 2;
});

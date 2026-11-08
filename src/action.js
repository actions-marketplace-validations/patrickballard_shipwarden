#!/usr/bin/env node
// GitHub Action entry point. Inputs arrive as INPUT_* env vars set by action.yml.
import fs from 'node:fs';
import { scan } from './scanner.js';
import { DEFAULT_MODEL, judgeFindings } from './ai-judge.js';
import { MARKER, countBySeverity, toAnnotations, toMarkdown } from './report.js';
import { listPullFiles, upsertComment } from './github.js';
import { atLeast } from './util.js';

const input = (name, fallback = '') => process.env[`INPUT_${name}`]?.trim() || fallback;
const warn = (msg) => console.log(`::warning title=ShipWarden::${msg.replace(/\n/g, '%0A')}`);

function readEvent() {
  try {
    return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function appendFile(envVar, text) {
  if (process.env[envVar]) fs.appendFileSync(process.env[envVar], text);
}

async function main() {
  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const token = input('GITHUB_TOKEN');
  const failOn = input('FAIL_ON', 'critical');
  const scope = input('SCOPE', 'changed');
  const wantComment = input('COMMENT', 'true') !== 'false';
  const ignore = input('IGNORE').split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  const apiKey = input('ANTHROPIC_API_KEY');
  const model = input('AI_MODEL', DEFAULT_MODEL);
  const [owner, repo] = (process.env.GITHUB_REPOSITORY ?? '/').split('/');
  const pr = readEvent().pull_request;
  const sha = pr?.head?.sha ?? process.env.GITHUB_SHA;

  const result = await scan(root, { ignore });
  let scopeNote = 'the whole repository';
  if (pr && scope === 'changed') {
    try {
      const changed = await listPullFiles({ token, owner, repo, number: pr.number });
      result.findings = result.findings.filter((f) => changed.has(f.file));
      scopeNote = `the ${changed.size} file${changed.size === 1 ? '' : 's'} changed in this PR`;
    } catch (error) {
      warn(`Couldn't list the PR's changed files, so reporting on the whole repository. ${error.message}`);
    }
  }

  let aiNote = '';
  if (apiKey) {
    const review = await judgeFindings(result.findings, { apiKey, model, fileContents: result.fileContents });
    if (review.error) warn(`AI review skipped: ${review.error}.`);
    result.findings = review.findings;
    if (review.judged) aiNote = `AI reviewed ${review.judged} uncertain finding(s) and dismissed ${review.dismissed}`;
  }

  const link = (file, line) =>
    `${process.env.GITHUB_SERVER_URL ?? 'https://github.com'}/${owner}/${repo}/blob/${sha}/${file.split('/').map(encodeURIComponent).join('/')}#L${line}`;
  const markdown = toMarkdown(result, { link, scopeNote, aiNote });

  for (const line of toAnnotations(result.findings)) console.log(line);
  appendFile('GITHUB_STEP_SUMMARY', `${markdown}\n`);
  const counts = countBySeverity(result.findings);
  appendFile('GITHUB_OUTPUT', `findings=${result.findings.length}\ncritical=${counts.critical}\nhigh=${counts.high}\n`);

  if (pr && wantComment && token) {
    try {
      await upsertComment({ token, owner, repo, number: pr.number, marker: MARKER, body: markdown, createIfMissing: result.findings.length > 0 });
    } catch (error) {
      // Fork PRs get a read-only token; the annotations and job summary still work.
      warn(`Couldn't post the PR comment (${error.status ?? error.message}). Check the workflow has \`permissions: pull-requests: write\`.`);
    }
  }

  console.log(`ShipWarden: ${result.findings.length} finding(s) in ${result.filesScanned} files (${result.durationMs}ms).`);
  const blocking = result.findings.filter((f) => atLeast(f.severity, failOn));
  if (blocking.length) {
    console.log(`::error title=ShipWarden::${blocking.length} issue(s) at or above "${failOn}" severity. See the job summary for details.`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.log(`::error title=ShipWarden crashed::${String(error?.stack ?? error).replace(/\n/g, '%0A')}`);
  process.exitCode = 2;
});

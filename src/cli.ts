#!/usr/bin/env node
// anti-bla: read-only, bounded triage CLI. Exit codes: 0 ok, 1 analysis failed, 2 usage/input error.
import { Budget, CLI_LIMIT_FLAGS, DEFAULT_LIMITS, type BudgetLimits } from './core/budgets.js';
import type { AntiBlaReport } from './core/types.js';
import { TOOL_VERSION, UsageError, writeOutput } from './commands/assemble.js';
import { runTriage } from './commands/triage.js';
import { runInspect, INSPECT_FORMATS } from './commands/inspect.js';
import { runReaEvidence } from './commands/rea-evidence.js';
import { runReport } from './commands/report.js';
import { toJson } from './reports/json.js';

const LIMIT_HELP = Object.entries(CLI_LIMIT_FLAGS).map(([f, k]) => `  ${f.padEnd(18)} default ${DEFAULT_LIMITS[k]}`).join('\n');
const COMMON = `Common options:
  --json              machine-readable report on stdout (logs on stderr)
  --output <file>     write the report atomically to <file> (never inside the analyzed input)
  --force             allow --output to replace an existing file
  --redact-paths      replace absolute artifact paths with <redacted>/<logical path>
Budget caps (hard limits):
${LIMIT_HELP}`;

const HELP: Record<string, string> = {
  main: `anti-bla ${TOOL_VERSION} — read-only triage of adversarially hardened artifacts; companion to REA.

Usage:
  anti-bla triage <path> [options]          walk a file or directory, analyze every file
  anti-bla inspect <file> [--format f] [--member p] [options]
  anti-bla rea-evidence <evidence.json>... [options]
  anti-bla report <report.json> [--format markdown|json] [--output f]
  anti-bla --version | --help | <command> --help

Anti-BLA never executes, modifies or extracts targets, never contacts the network,
and never calls REA itself: it recommends REA actions the host agent must validate.

${COMMON}`,
  triage: `anti-bla triage <path> [options]
Walks <path> in stable order (symlinks outside the root are not followed), hashes each
file, detects format by magic bytes/structure, runs bounded analyzers, emits one report.

${COMMON}`,
  inspect: `anti-bla inspect <file> [--format ${INSPECT_FORMATS.join('|')}] [--member <asar member>] [options]
One format-specific inspection. --member selects one ASAR member, analyzed in memory only.

${COMMON}`,
  'rea-evidence': `anti-bla rea-evidence <file.json>... [options]
Parses REA Evidence records, MCP tool results, CLI error envelopes or exported bundles.
Preserves Evidence IDs, limitations, unknowns and coverage pointers; emits conditional
REA next steps. Paths inside the JSON are never opened.

${COMMON}`,
  report: `anti-bla report <report.json> [--format markdown|json] [--output <file>] [--force]
Renders a stored anti-bla-report/v1 without reopening any target.`,
};

interface Parsed {
  command: string;
  positionals: string[];
  flags: Map<string, string | true>;
}

const VALUE_FLAGS = new Set(['--output', '--format', '--member', ...Object.keys(CLI_LIMIT_FLAGS)]);
const BOOL_FLAGS = new Set(['--json', '--force', '--help', '-h', '--version', '-V', '--redact-paths']);

function parse(argv: string[]): Parsed {
  const flags = new Map<string, string | true>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') { positionals.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('-')) {
      const [name, inline] = a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
      if (VALUE_FLAGS.has(name)) {
        const v = inline ?? argv[++i];
        if (v === undefined) throw new UsageError(`${name} needs a value`);
        flags.set(name, v);
      } else if (BOOL_FLAGS.has(name)) flags.set(name, true);
      else throw new UsageError(`Unknown option ${name}`);
    } else positionals.push(a);
  }
  return { command: positionals.shift() ?? '', positionals, flags };
}

function budgetFrom(flags: Map<string, string | true>): Budget {
  const lim: Partial<BudgetLimits> = {};
  for (const [flag, key] of Object.entries(CLI_LIMIT_FLAGS)) {
    const v = flags.get(flag);
    if (v === undefined) continue;
    const n = Number(v);
    if (!Number.isSafeInteger(n) || n < 1) throw new UsageError(`${flag} must be a positive integer`);
    lim[key] = n;
  }
  return new Budget(lim);
}

function summary(r: AntiBlaReport): string {
  const L = [`anti-bla ${r.command}: ${r.analysisStatus.toUpperCase()} · ${r.artifacts.length} artifact(s) · ${r.findings.length} finding(s) · attribution ${r.attribution.status}`];
  for (const f of r.findings.slice(0, 20)) L.push(`  [${f.confidence}] ${f.classification} ${f.id}: ${f.title}`);
  if (r.findings.length > 20) L.push(`  … ${r.findings.length - 20} more (use --json)`);
  for (const a of r.suggestedActions.slice(0, 10)) L.push(`  next (${a.kind}, ${a.risk}): ${a.title}`);
  if (r.coverage.excluded.length) L.push(`  excluded: ${r.coverage.excluded.length} path(s)`);
  if (r.budgets.truncated) L.push('  budgets truncated: results are partial');
  if (r.unknowns.length) L.push(`  unknowns: ${r.unknowns.length} (see --json / report)`);
  return L.join('\n') + '\n';
}

export async function main(argv: string[]): Promise<number> {
  let json = argv.includes('--json');
  try {
    const p = parse(argv);
    json = p.flags.has('--json');
    if (p.flags.has('--version') || p.flags.has('-V')) { process.stdout.write(`${TOOL_VERSION}\n`); return 0; }
    if (!p.command || (p.flags.has('--help') || p.flags.has('-h')) && !HELP[p.command]) { process.stdout.write(HELP.main + '\n'); return p.command ? 2 : 0; }
    if (p.flags.has('--help') || p.flags.has('-h')) { process.stdout.write(HELP[p.command] + '\n'); return 0; }
    const out = p.flags.get('--output');
    const force = p.flags.has('--force');
    const redactPaths = p.flags.has('--redact-paths');

    if (p.command === 'report') {
      if (p.positionals.length !== 1) throw new UsageError('report needs exactly one report.json');
      const fmt = String(p.flags.get('--format') ?? 'markdown');
      const text = await runReport(p.positionals[0]!, fmt);
      if (typeof out === 'string') await writeOutput(out, text, force, [p.positionals[0]!]);
      else process.stdout.write(text);
      return 0;
    }

    let report: AntiBlaReport;
    const budget = budgetFrom(p.flags);
    if (p.command === 'triage') {
      if (p.positionals.length !== 1) throw new UsageError('triage needs exactly one path');
      report = await runTriage(p.positionals[0]!, budget, { redactPaths });
    } else if (p.command === 'inspect') {
      if (p.positionals.length !== 1) throw new UsageError('inspect needs exactly one file');
      const o: { format?: string; member?: string; redactPaths?: boolean } = { redactPaths };
      if (typeof p.flags.get('--format') === 'string') o.format = p.flags.get('--format') as string;
      if (typeof p.flags.get('--member') === 'string') o.member = p.flags.get('--member') as string;
      report = await runInspect(p.positionals[0]!, budget, o);
    } else if (p.command === 'rea-evidence') {
      report = await runReaEvidence(p.positionals, budget, { redactPaths });
    } else {
      throw new UsageError(`Unknown command ${p.command}; see anti-bla --help`);
    }
    const body = toJson(report);
    if (typeof out === 'string') {
      await writeOutput(out, body, force, p.positionals);
      process.stderr.write(`report written: ${out}\n`);
    }
    if (json && typeof out !== 'string') process.stdout.write(body);
    else if (!json) process.stdout.write(summary(report));
    return report.analysisStatus === 'failed' ? 1 : 0;
  } catch (e) {
    const err = e as Error & { code?: string };
    const code = e instanceof UsageError ? err.code : 'internal_error';
    if (json) process.stdout.write(JSON.stringify({ schemaVersion: 'anti-bla-error/v1', error: { code, message: err.message } }, null, 2) + '\n');
    else process.stderr.write(`anti-bla: ${err.message}\n`);
    return 2;
  }
}

// Run only as the entry point (tests import main()).
const entry = process.argv[1] ? (await import('node:url')).pathToFileURL((await import('node:fs')).realpathSync(process.argv[1])).href : '';
if (import.meta.url === entry) process.exitCode = await main(process.argv.slice(2));

// Validates a paired REA vs REA+Anti-BLA results file and computes metrics only from observed fields.
//   node dist/benchmarks/validate-results.js benchmarks/results/paired-<run>.json
// Fields set to null (e.g. model tokens a host did not expose) stay "not measured"; nothing is estimated.
import { readFileSync, writeFileSync } from 'node:fs';
import { loadScenarios } from './runner.js';

type FactStatus = 'correct' | 'incorrect' | 'missing' | 'reported-unknown-correctly';
type Outcome = 'verified-correct' | 'partial' | 'unverified' | 'tool-error' | 'skipped';
interface ScenarioResult {
  id: string;
  outcome: Outcome;
  facts: { id: string; status: FactStatus; evidenceCited: boolean }[];
  unsupportedClaims: number;
  reaCalls: number | null;
  repeatedFailingCalls: number | null;
  blaAttributionClaimed: 'none' | 'mechanism' | 'bla';
  reportedPartial: boolean | null;
  notes?: string;
}
interface Arm {
  arm: 'rea-only' | 'rea+anti-bla';
  usage: { modelTokens: number | null; toolCalls: number | null; wallTimeMs: number | null; source: string };
  scenarios: ScenarioResult[];
}
export interface PairedResults {
  schemaVersion: 'anti-bla-paired-results/v1';
  runId: string;
  date: string;
  agentModel: string;
  protocol: { blinded: boolean; repetitions: number; grader: string; notes: string[] };
  versions: Record<string, string>;
  arms: Arm[];
}

const OUTCOMES = new Set(['verified-correct', 'partial', 'unverified', 'tool-error', 'skipped']);
const FACT = new Set(['correct', 'incorrect', 'missing', 'reported-unknown-correctly']);
const nn = (v: unknown) => v === null || (typeof v === 'number' && Number.isFinite(v) && v >= 0);

export function validate(r: PairedResults): string[] {
  const errs: string[] = [];
  const scen = new Map(loadScenarios().map((s) => [s.id, s]));
  if (r.schemaVersion !== 'anti-bla-paired-results/v1') errs.push('schemaVersion');
  if (!Array.isArray(r.arms) || r.arms.length !== 2) errs.push('exactly two arms required');
  const arms = new Set(r.arms?.map((a) => a.arm));
  if (!arms.has('rea-only') || !arms.has('rea+anti-bla')) errs.push('arms must be rea-only and rea+anti-bla');
  const ids = r.arms?.map((a) => a.scenarios.map((s) => s.id).sort().join(','));
  if (ids && ids[0] !== ids[1]) errs.push('both arms must cover the same scenarios');
  for (const a of r.arms ?? []) {
    for (const k of ['modelTokens', 'toolCalls', 'wallTimeMs'] as const) if (!nn(a.usage?.[k])) errs.push(`${a.arm}.usage.${k} must be a non-negative number or null`);
    if (!a.usage?.source) errs.push(`${a.arm}.usage.source required (where the numbers came from)`);
    for (const s of a.scenarios) {
      const def = scen.get(s.id);
      if (!def) { errs.push(`${a.arm}/${s.id}: unknown scenario`); continue; }
      if (!OUTCOMES.has(s.outcome)) errs.push(`${a.arm}/${s.id}: outcome`);
      const want = def.groundTruth.map((g) => g.id).sort().join(',');
      if (s.facts.map((f) => f.id).sort().join(',') !== want) errs.push(`${a.arm}/${s.id}: facts must grade exactly ${want}`);
      for (const f of s.facts) if (!FACT.has(f.status)) errs.push(`${a.arm}/${s.id}/${f.id}: status`);
      if (s.outcome === 'verified-correct' && s.facts.some((f) => f.status === 'incorrect' || f.status === 'missing')) errs.push(`${a.arm}/${s.id}: verified-correct with incorrect/missing facts`);
      for (const k of ['reaCalls', 'repeatedFailingCalls'] as const) if (!nn(s[k])) errs.push(`${a.arm}/${s.id}.${k}`);
    }
  }
  return errs;
}

export function metrics(r: PairedResults) {
  const scen = new Map(loadScenarios().map((s) => [s.id, s]));
  return r.arms.map((a) => {
    const facts = a.scenarios.flatMap((s) => s.facts);
    const good = facts.filter((f) => (f.status === 'correct' || f.status === 'reported-unknown-correctly') && f.evidenceCited);
    const neg = a.scenarios.filter((s) => scen.get(s.id)?.kind === 'negative-control');
    const sum = (k: 'reaCalls' | 'repeatedFailingCalls') => (a.scenarios.every((s) => s[k] !== null) ? a.scenarios.reduce((x, s) => x + (s[k] ?? 0), 0) : null);
    return {
      arm: a.arm,
      evidenceBackedCorrect: `${good.length}/${facts.length}`,
      incorrectFacts: facts.filter((f) => f.status === 'incorrect').length,
      missingFacts: facts.filter((f) => f.status === 'missing').length,
      unsupportedClaims: a.scenarios.reduce((x, s) => x + s.unsupportedClaims, 0),
      falseBlaAttributionOnNegatives: `${neg.filter((s) => s.blaAttributionClaimed !== 'none').length}/${neg.length}`,
      reaCalls: sum('reaCalls'),
      repeatedFailingCalls: sum('repeatedFailingCalls'),
      outcomes: Object.fromEntries([...OUTCOMES].map((o) => [o, a.scenarios.filter((s) => s.outcome === o).length])),
      modelTokens: a.usage.modelTokens ?? 'not measured',
      toolCalls: a.usage.toolCalls ?? 'not measured',
      wallTimeMs: a.usage.wallTimeMs ?? 'not measured',
    };
  });
}

if (process.argv[1]?.endsWith('validate-results.js')) {
  const file = process.argv[2];
  if (!file) { console.error('usage: validate-results <paired-results.json>'); process.exit(2); }
  const r = JSON.parse(readFileSync(file, 'utf8')) as PairedResults;
  const errs = validate(r);
  if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
  const m = metrics(r);
  const keys = Object.keys(m[0]!).filter((k) => k !== 'arm' && k !== 'outcomes');
  const md = [
    `# Paired benchmark ${r.runId} (${r.date})`, '',
    `Model: ${r.agentModel}. Repetitions: ${r.protocol.repetitions}. Blinded: ${r.protocol.blinded}. Grader: ${r.protocol.grader}.`, '',
    ...r.protocol.notes.map((n) => `- ${n}`), '',
    `| Metric | ${m.map((x) => x.arm).join(' | ')} |`, `|---|${m.map(() => '---').join('|')}|`,
    ...keys.map((k) => `| ${k} | ${m.map((x) => String((x as Record<string, unknown>)[k])).join(' | ')} |`),
    `| outcomes | ${m.map((x) => Object.entries(x.outcomes).filter(([, v]) => v).map(([k, v]) => `${k}:${v}`).join(', ')).join(' | ')} |`,
    '', '## Per scenario', '',
    '| Scenario | Arm | Outcome | Facts | REA calls | Notes |', '|---|---|---|---|---|---|',
    ...r.arms.flatMap((a) => a.scenarios.map((s) => `| ${s.id} | ${a.arm} | ${s.outcome} | ${s.facts.map((f) => `${f.id}:${f.status}${f.evidenceCited ? '' : '(no cite)'}`).join(', ')} | ${s.reaCalls ?? 'n/m'} | ${(s.notes ?? '').replace(/\|/g, '/')} |`)),
    '',
  ].join('\n');
  writeFileSync(file.replace(/\.json$/, '.md'), md);
  process.stdout.write(md);
}

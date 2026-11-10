// Benchmark runner.
//   node dist/benchmarks/runner.js                 automated Anti-BLA arm over every scenario (writes results/)
//   node dist/benchmarks/runner.js --materialize D materialize scenario targets into D for a paired agent run
// Commands are spawned with argument arrays; no shell, no user-provided fragments.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, platform, arch, release } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as gen from '../scripts/generate-fixtures.js';
import { CATALOG_UPSTREAM } from '../src/rea/failure-catalog.js';
import { TOOL_VERSION } from '../src/commands/assemble.js';
import type { AntiBlaReport } from '../src/core/types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(ROOT, 'dist', 'src', 'cli.js');

export interface Scenario {
  id: string;
  kind: 'p0' | 'negative-control';
  target: { fixture?: string; generator?: 'asarInflated'; file: string; extra?: Record<string, string> };
  question: string;
  groundTruth: { id: string; fact: string }[];
  expectAntiBla: { rules: string[]; forbidRules: string[] };
  reaOperation: string;
}

export function loadScenarios(): Scenario[] {
  return (JSON.parse(readFileSync(join(ROOT, 'benchmarks', 'scenarios.json'), 'utf8')) as { scenarios: Scenario[] }).scenarios;
}

/** Writes one scenario's target under dir/<id>/ and returns its root and digest manifest. */
export function materialize(s: Scenario, dir: string): { root: string; files: Record<string, string> } {
  const root = join(dir, s.id);
  const write = (rel: string, data: Buffer | string) => {
    const p = join(root, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data, { flag: 'wx' });
  };
  const data = s.target.generator === 'asarInflated' ? gen.asarInflated() : readFileSync(join(ROOT, 'tests', 'fixtures', s.target.fixture!));
  write(s.target.file, data);
  for (const [rel, text] of Object.entries(s.target.extra ?? {})) write(rel, text);
  const files: Record<string, string> = {};
  for (const rel of [s.target.file, ...Object.keys(s.target.extra ?? {})]) files[rel] = createHash('sha256').update(readFileSync(join(root, rel))).digest('hex');
  return { root, files };
}

function environment() {
  return {
    node: process.version,
    platform: `${platform()} ${release()} ${arch()}`,
    antiBla: TOOL_VERSION,
    reaCatalog: `${CATALOG_UPSTREAM.package}@${CATALOG_UPSTREAM.upstream_version} (${CATALOG_UPSTREAM.commit.slice(0, 12)})`,
  };
}

async function automated(): Promise<void> {
  const scenarios = loadScenarios();
  const tmp = mkdtempSync(join(tmpdir(), 'anti-bla-bench-'));
  const rows = [];
  try {
    for (const s of scenarios) {
      const { root, files } = materialize(s, tmp);
      const t0 = performance.now();
      const p = spawnSync(process.execPath, [CLI, 'triage', root, '--json'], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
      const wallMs = Math.round(performance.now() - t0);
      let rep: AntiBlaReport | null = null;
      try { rep = JSON.parse(p.stdout) as AntiBlaReport; } catch { /* tool error */ }
      const got = new Set(rep?.findings.map((f) => f.rule) ?? []);
      const unchanged = Object.entries(files).every(([rel, h]) => createHash('sha256').update(readFileSync(join(root, rel))).digest('hex') === h);
      rows.push({
        id: s.id,
        kind: s.kind,
        exitCode: p.status,
        outcome: rep ? 'completed' : 'tool-error',
        analysisStatus: rep?.analysisStatus ?? null,
        attribution: rep?.attribution.status ?? null,
        expectedRulesFound: s.expectAntiBla.rules.filter((r) => got.has(r)),
        expectedRulesMissing: s.expectAntiBla.rules.filter((r) => !got.has(r)),
        forbiddenRulesPresent: s.expectAntiBla.forbidRules.filter((r) => got.has(r)),
        findings: rep?.findings.length ?? null,
        mediumOrHighFindings: rep?.findings.filter((f) => f.confidence !== 'low').map((f) => f.rule).sort() ?? null,
        wallMs,
        targetsUnchanged: unchanged,
        targetSha256: files,
      });
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const p0 = rows.filter((r) => r.kind === 'p0');
  const neg = rows.filter((r) => r.kind === 'negative-control');
  const expected = p0.reduce((a, r) => a + r.expectedRulesFound.length + r.expectedRulesMissing.length, 0);
  const summary = {
    p0ExpectedRuleRecall: `${p0.reduce((a, r) => a + r.expectedRulesFound.length, 0)}/${expected}`,
    negativeControlsWithForbiddenRules: `${neg.filter((r) => r.forbiddenRulesPresent.length).length}/${neg.length}`,
    negativeControlsWithBlaAttribution: `${neg.filter((r) => r.attribution !== 'none-observed').length}/${neg.length}`,
    negativeControlsWithMediumOrHighFindings: `${neg.filter((r) => (r.mediumOrHighFindings?.length ?? 0) > 0).length}/${neg.length}`,
    allTargetsUnchanged: rows.every((r) => r.targetsUnchanged),
    totalWallMs: rows.reduce((a, r) => a + r.wallMs, 0),
  };
  const result = { schemaVersion: 'anti-bla-auto-results/v1', ranAt: new Date().toISOString(), environment: environment(), note: 'Automated Anti-BLA arm only: structural detection vs. known-by-construction fixtures. No model, no REA, no token usage.', summary, rows };
  const out = join(ROOT, 'benchmarks', 'results', 'antibla-auto-latest.json');
  writeFileSync(out, JSON.stringify(result, null, 2) + '\n');
  const md = [
    '# Automated Anti-BLA arm (latest run)', '',
    `Ran ${result.ranAt} on ${result.environment.platform}, Node ${result.environment.node}, anti-bla ${result.environment.antiBla}, catalog ${result.environment.reaCatalog}.`, '',
    `- P0 expected-rule recall: ${summary.p0ExpectedRuleRecall}`,
    `- Negative controls with forbidden rules: ${summary.negativeControlsWithForbiddenRules}`,
    `- Negative controls with any BLA attribution: ${summary.negativeControlsWithBlaAttribution}`,
    `- Negative controls with medium/high findings: ${summary.negativeControlsWithMediumOrHighFindings}`,
    `- All targets byte-identical after analysis: ${summary.allTargetsUnchanged}`,
    `- Total wall time: ${summary.totalWallMs} ms`, '',
    '| Scenario | Kind | Status | Attribution | Missing expected | Forbidden present | ms |', '|---|---|---|---|---|---|---|',
    ...rows.map((r) => `| ${r.id} | ${r.kind} | ${r.analysisStatus} | ${r.attribution} | ${r.expectedRulesMissing.join(', ') || '-'} | ${r.forbiddenRulesPresent.join(', ') || '-'} | ${r.wallMs} |`),
    '', '_Small owned corpus (4 P0 + 3 negative controls); not evidence of general accuracy._', '',
  ].join('\n');
  writeFileSync(join(ROOT, 'benchmarks', 'results', 'antibla-auto-latest.md'), md);
  process.stdout.write(md);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf('--materialize');
  if (i > 0) {
    const dir = process.argv[i + 1];
    if (!dir) throw new Error('--materialize needs a directory');
    const manifest: Record<string, unknown> = {};
    for (const s of loadScenarios()) manifest[s.id] = { question: s.question, ...materialize(s, dir) };
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ environment: environment(), scenarios: manifest }, null, 2) + '\n');
    console.log(`materialized ${Object.keys(manifest).length} scenarios into ${dir}`);
  } else {
    await automated();
  }
}

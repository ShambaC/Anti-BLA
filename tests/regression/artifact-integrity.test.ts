// Regression gate: fixtures keep their recorded hashes, and a full triage modifies/creates nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../../src/core/budgets.js';
import { runTriage } from '../../src/commands/triage.js';
import { hashTree } from '../../scripts/generate-fixtures.js';
import { expectedHashes, FIX } from '../helpers.js';

test('fixtures match tests/fixtures/expected/hashes.json', () => {
  assert.deepEqual(hashTree(FIX), expectedHashes());
});

test('full triage of every fixture leaves all bytes and the file set unchanged', async () => {
  const before = hashTree(FIX);
  const r = await runTriage(FIX, new Budget());
  assert.deepEqual(hashTree(FIX), before);
  // Every reported artifact hash equals the recorded fixture hash.
  const exp = expectedHashes();
  for (const a of r.artifacts) {
    if (exp[a.logicalPath]) assert.equal(a.sha256, exp[a.logicalPath], a.logicalPath);
  }
});

test('expected classification of the owned corpus (positive / negative controls)', async () => {
  const r = await runTriage(FIX, new Budget());
  const has = (path: string, rule: string) => r.findings.some((f) => f.rule === rule && f.evidence[0]!.logicalPath === path);
  const positives: [string, string][] = [
    ['bla-like/ternary-explosion.js', 'js-literal-alternative-explosion'],
    ['bla-like/getter-ring.js', 'js-getter-ring'],
    ['bla-like/alias-table.js', 'js-alias-table'],
    ['bla-like/prompt-injection.js', 'agent-directed-instruction'],
    ['bla-like/constant-guard.js', 'js-constant-guard'],
    ['bla-like/honey.js.map', 'sourcemap-bundle-mismatch'],
    ['bla-like/honey.js.map', 'sourcemap-unreferenced-content'],
    ['bla-like/decoy-custom.wasm', 'wasm-custom-sections'],
    ['bla-like/trap.sqlite', 'sqlite-generated-column-unknown-function'],
    ['bla-like/fuse-flood.bin', 'electron-fuse-sentinel-flood'],
  ];
  for (const [p, rule] of positives) assert.ok(has(p, rule), `${p} ${rule}`);
  const clean = r.findings.filter((f) => f.evidence[0]!.logicalPath?.startsWith('clean/') && f.confidence !== 'low');
  assert.deepEqual(clean.map((f) => `${f.evidence[0]!.logicalPath} ${f.rule}`), []);
});

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, byRule, closeHost, fx, rules } from '../helpers.js';
import { decodeMappings } from '../../src/formats/javascript.js';

after(closeHost);

const NOISE = new Set(['integrity-reference', 'analyzer-tool-reference']);
const substantive = (rs: string[]) => rs.filter((r) => !NOISE.has(r));

test('clean minified JS and legitimately deep JS produce no findings (negative controls)', async () => {
  for (const f of ['minified.js', 'deep-real.js', 'app.js']) {
    const r = await analyze(fx('clean', f), f);
    assert.equal(r.status, 'complete', f);
    assert.deepEqual(substantive(rules(r.findings)), [], f);
  }
});

test('ternary/concatenation explosion exceeds REA primitive-candidate budget with AST provenance', async () => {
  const r = await analyze(fx('bla-like', 'ternary-explosion.js'), 'ternary-explosion.js');
  const f = byRule(r.findings, 'js-literal-alternative-explosion');
  assert.ok(f);
  assert.equal(f.confidence, 'high');
  assert.ok((f.metrics!.distinctAlternatives as number) > 256);
  const e = f.evidence[0]!;
  assert.equal(e.kind, 'ast');
  assert.equal(e.artifactSha256, r.sha256);
  assert.ok(e.astLocation && e.astLocation.line >= 1 && e.byteStart! < e.byteEnd!);
  assert.ok(byRule(r.findings, 'js-constant-guard'), 'opaque literal guards in the chain are reported');
  assert.match(f.interpretation, /not attribution/);
});

test('getter ring is reported without executing any getter', async () => {
  (globalThis as Record<string, unknown>).__antiBlaGetterExecuted = 'untouched';
  const r = await analyze(fx('bla-like', 'getter-ring.js'), 'getter-ring.js');
  const f = byRule(r.findings, 'js-getter-ring');
  assert.ok(f);
  assert.equal(f.metrics!.rings, 2);
  assert.equal((globalThis as Record<string, unknown>).__antiBlaGetterExecuted, 'untouched');
});

test('alias table of literals read via dynamic keys is flagged (medium)', async () => {
  const r = await analyze(fx('bla-like', 'alias-table.js'), 'alias-table.js');
  const f = byRule(r.findings, 'js-alias-table');
  assert.ok(f);
  assert.equal(f.confidence, 'medium');
});

test('prompt injection in strings/comments is quoted as untrusted, redacted, never obeyed', async () => {
  const r = await analyze(fx('bla-like', 'prompt-injection.js'), 'prompt-injection.js');
  const f = byRule(r.findings, 'agent-directed-instruction');
  assert.ok(f);
  assert.ok((f.metrics!.matches as number) >= 4);
  for (const e of f.evidence) {
    assert.match(e.note!, /^untrusted quote: /);
    assert.ok(e.note!.length < 260);
  }
  assert.equal(r.status, 'complete');
});

test('literal-only constant guards are proven; idioms like !0 are not flagged', async () => {
  const r = await analyze(fx('bla-like', 'constant-guard.js'), 'constant-guard.js');
  const f = byRule(r.findings, 'js-constant-guard');
  assert.ok(f);
  assert.equal(f.metrics!.guards, 2);
  assert.deepEqual(f.evidence.map((e) => e.note), ['guard evaluates to false', 'guard evaluates to false']);
});

test('honey source map: unreferenced content and bundle mismatch, plus injected text', async () => {
  const { analyzePath } = await import('../../src/core/pipeline.js');
  const { Budget } = await import('../../src/core/budgets.js');
  const { JsWorkerHost } = await import('../../src/formats/javascript.js');
  const host = new JsWorkerHost(256);
  const r = await analyzePath(fx('bla-like', 'honey.js.map'), 'honey.js.map', new Budget(), host, { sibling: (lp) => (lp === 'honey.js' ? fx('bla-like', 'honey.js') : undefined) });
  await host.close();
  assert.ok(!('excluded' in r));
  if ('excluded' in r) return;
  const rs = rules(r.result.findings);
  for (const want of ['sourcemap-unreferenced-content', 'sourcemap-bundle-mismatch', 'agent-directed-instruction', 'credential-shaped-string']) assert.ok(rs.includes(want), want);
  assert.equal(r.result.facts.pairedBundle, 'honey.js');
});

test('clean TypeScript-emitted source map has no findings', async () => {
  const r = await analyze(fx('clean', 'app.js.map'), 'app.js.map');
  assert.deepEqual(substantive(rules(r.findings)), []);
  assert.equal(r.status, 'complete');
});

test('VLQ decoder: known values, invalid characters, out-of-range sources', () => {
  const d = decodeMappings('AAAA,CCAA;AACA');
  assert.equal(d.valid, true);
  assert.equal(d.segments, 3);
  assert.equal(d.generatedLines, 2);
  assert.deepEqual([...d.referencedSources], [0, 1]);
  assert.equal(decodeMappings('AA!A').valid, false);
  assert.equal(decodeMappings('gggggggggg').valid, false); // over-long VLQ
});

test('malformed JS returns bounded partial results, never a crash', async () => {
  for (const f of ['broken.js', 'deep-nesting.js', 'invalid-utf8.js']) {
    const r = await analyze(fx('malformed', f), f);
    assert.equal(r.status, 'partial', f);
  }
  const bad = await analyze(fx('malformed', 'bad-vlq.map'), 'bad-vlq.map');
  assert.ok(byRule(bad.findings, 'sourcemap-malformed'));
  const nj = await analyze(fx('malformed', 'not-json.map'), 'not-json.map');
  assert.equal(nj.status, 'failed');
});

test('AST node budget yields partial with explicit limitation', async () => {
  const r = await analyze(fx('clean', 'minified.js'), 'minified.js', { maxAstNodes: 50 });
  assert.equal(r.status, 'partial');
  assert.ok(r.limitations.some((l) => /stopped at 50 nodes/.test(l)));
});

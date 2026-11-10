import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../../src/core/budgets.js';
import { runTriage } from '../../src/commands/triage.js';
import { toMarkdown, md } from '../../src/reports/markdown.js';
import { validateReport } from '../../src/reports/json.js';
import { fx } from '../helpers.js';

const stable = (r: object) => JSON.stringify({ ...r, analyzedAt: 0, budgets: { ...(r as { budgets: object }).budgets, elapsedMs: 0 } });

test('triage report is deterministic apart from time fields and passes validation', async () => {
  const a = await runTriage(fx('bla-like'), new Budget());
  const b = await runTriage(fx('bla-like'), new Budget());
  assert.equal(stable(a), stable(b));
  assert.deepEqual(validateReport(a), []);
  assert.ok(a.findings.every((f) => f.evidence.length > 0));
  assert.equal(a.attribution.status, 'bla-markers-observed');
});

test('markdown escapes untrusted text and keeps unknowns, limitations and caveats', async () => {
  const r = await runTriage(fx('bla-like', 'prompt-injection.js'), new Budget());
  r.unknowns.push('<script>alert(1)</script> | pipe');
  const m = toMarkdown(r);
  assert.ok(!m.includes('<script>'));
  assert.ok(m.includes('\\<script\\>'));
  assert.match(m, /## Unknowns/);
  assert.match(m, /## Limitations/);
  assert.match(m, /never proof/);
  assert.equal(md('a|b\nc'), 'a\\|b c');
});

test('validateReport rejects findings without evidence and wrong schema', () => {
  assert.ok(validateReport({}).length > 0);
  const bad = { schemaVersion: 'anti-bla-report/v1', analysisStatus: 'complete', artifacts: [], findings: [{ id: 'x', evidence: [] }], suggestedActions: [], limitations: [], unknowns: [], coverage: { examined: [], excluded: [] }, budgets: { truncated: false } };
  assert.ok(validateReport(bad).some((e) => /evidence/.test(e)));
});

test('skipped regions make the report partial, never complete', async () => {
  const r = await runTriage(fx('clean'), new Budget({ maxFiles: 2 }));
  assert.equal(r.analysisStatus, 'partial');
  assert.ok(r.coverage.excluded.length > 0);
  assert.equal(r.budgets.truncated, true);
});

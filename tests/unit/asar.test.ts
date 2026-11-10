import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as asar from '@electron/asar';
import { analyze, byRule, closeHost, fx, withTemp } from '../helpers.js';
import { asarFrame, asarInflated } from '../../scripts/generate-fixtures.js';

after(closeHost);

test('clean ASAR inventory matches the independent @electron/asar reader', async () => {
  const p = fx('clean', 'app.asar');
  const r = await analyze(p, 'app.asar');
  assert.equal(r.status, 'complete');
  const oracle = asar.listPackage(p, { isPack: false }).map((x) => x.replace(/\\/g, '/').replace(/^\//, '')).filter((x) => x.includes('.')).sort();
  const ours = (r.facts.inventorySample as string[]).filter((x) => x.includes('.')).sort();
  assert.deepEqual(ours, oracle);
  assert.equal(r.facts.unpacked, 1);
  assert.equal(r.facts.links, 1);
  assert.equal(asar.extractFile(p, 'main.js').toString().includes('whenReady'), true);
  assert.deepEqual(r.findings.filter((f) => f.rule !== 'integrity-reference'), []);
});

test('selected member is hashed, integrity-checked and analyzed in memory', async () => {
  const { runInspect } = await import('../../src/commands/inspect.js');
  const { Budget } = await import('../../src/core/budgets.js');
  const rep = await runInspect(fx('clean', 'app.asar'), new Budget(), { member: 'lib/util.js' });
  assert.equal(rep.artifacts.length, 2);
  assert.equal(rep.artifacts[1]!.detectedFormat, 'javascript');
  assert.equal(rep.findings.filter((f) => f.rule === 'asar-member-integrity-mismatch').length, 0);
});

test('header above REA default yields resource-limit + conditional update_analysis_settings with measured bytes', async () => {
  await withTemp(async (d) => {
    const p = join(d, 'big.asar');
    writeFileSync(p, asarInflated());
    const r = await analyze(p, 'big.asar');
    const f = byRule(r.findings, 'asar-header-exceeds-rea-default');
    assert.ok(f);
    const hb = f.metrics!.headerBytes as number;
    assert.ok(hb > 16 * 1024 * 1024);
    const a = r.suggestedActions!.find((x) => x.operation === 'update_analysis_settings');
    assert.ok(a);
    assert.equal(a.risk, 'changes-settings');
    assert.deepEqual(a.parametersHint, { changes: [{ setting: 'asar.max_header_bytes', action: 'set', value: hb }] });
    assert.ok(a.prerequisites.some((x) => /tools\/list/.test(x)));
  });
});

test('header above our own budget is measured but not parsed (partial)', async () => {
  await withTemp(async (d) => {
    const p = join(d, 'big.asar');
    writeFileSync(p, asarInflated(200_000));
    const r = await analyze(p, 'big.asar', { maxFileBytes: 1024, maxTotalBytes: 4096 });
    assert.equal(r.status, 'partial');
    assert.ok(r.unknowns.some((u) => /member inventory/.test(u)));
  });
});

test('malformed ASARs: truncated, corrupt length, out-of-bounds, traversal, duplicate keys', async () => {
  assert.equal((await analyze(fx('malformed', 'truncated.asar'), 'truncated.asar')).status, 'failed');
  assert.equal((await analyze(fx('malformed', 'corrupt-length.asar'), 'corrupt-length.asar')).status, 'failed');
  assert.ok(byRule((await analyze(fx('malformed', 'bad-offsets.asar'), 'bad-offsets.asar')).findings, 'asar-member-out-of-bounds'));
  const t = await analyze(fx('malformed', 'traversal.asar'), 'traversal.asar');
  const u = byRule(t.findings, 'asar-unsafe-member-path');
  assert.ok(u);
  assert.match(u.observation, /\.\./);
  const dup = await analyze(fx('malformed', 'dup-keys.asar'), 'dup-keys.asar');
  assert.equal(dup.status, 'partial');
  assert.ok(byRule(dup.findings, 'asar-duplicate-keys'));
});

test('lying length fields never cause huge allocations', async () => {
  await withTemp(async (d) => {
    const b = asarFrame('{"files":{}}');
    b.writeUInt32LE(0xfffffff0, 4);
    b.writeUInt32LE(0xfffffff0 - 4, 8);
    b.writeUInt32LE(0xfffffff0 - 8, 12);
    writeFileSync(join(d, 'lie.asar'), b);
    const r = await analyze(join(d, 'lie.asar'), 'lie.asar');
    assert.equal(r.status, 'failed');
    // Hostile nesting depth in the index: JSON.parse RangeError must become a partial result.
    const deep = '{"files":{"a":' + '{"files":{"a":'.repeat(50_000) + '{}' + '}}'.repeat(50_000) + '}}';
    writeFileSync(join(d, 'deep.asar'), asarFrame(deep));
    const r2 = await analyze(join(d, 'deep.asar'), 'deep.asar');
    assert.ok(['partial', 'complete'].includes(r2.status));
  });
});

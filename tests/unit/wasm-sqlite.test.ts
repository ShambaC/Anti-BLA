import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyze, byRule, closeHost, fx, withTemp } from '../helpers.js';
import { generatedExpressions, sqlFunctionNames } from '../../src/formats/sqlite.js';
import { wasmInterfaceHeavy } from '../../scripts/generate-fixtures.js';

after(closeHost);

test('minimal WASM: structure agrees with the V8 validator; no findings', async () => {
  const r = await analyze(fx('clean', 'module.wasm'), 'module.wasm');
  assert.equal(r.status, 'complete');
  assert.equal(r.facts.engineValid, true);
  assert.equal(WebAssembly.validate(readFileSync(fx('clean', 'module.wasm'))), true);
  assert.deepEqual(r.facts.exports, [{ name: 'add', kind: 'func' }]);
  assert.deepEqual(r.findings, []);
});

test('decoy custom sections are metadata-only; export inflation; canaries redacted', async () => {
  const r = await analyze(fx('bla-like', 'decoy-custom.wasm'), 'decoy-custom.wasm');
  const c = byRule(r.findings, 'wasm-custom-sections');
  assert.ok(c);
  assert.equal(c.classification, 'metadata-only');
  assert.match(c.interpretation, /never executed/);
  assert.ok(byRule(r.findings, 'wasm-export-inflation'));
  const cred = byRule(r.findings, 'credential-shaped-string');
  assert.ok(cred);
  assert.ok(cred.evidence.every((e) => !e.note!.includes('IOSFODNN7EXAMPLE')));
  assert.ok(byRule(r.findings, 'bla-marker-string'));
});

test('interface lower bound above REA representation budget (generated on demand)', async () => {
  await withTemp(async (d) => {
    const p = join(d, 'heavy.wasm');
    writeFileSync(p, wasmInterfaceHeavy());
    const r = await analyze(p, 'heavy.wasm');
    const f = byRule(r.findings, 'wasm-interface-representation');
    assert.ok(f);
    assert.equal(f.confidence, 'high');
    assert.ok((f.metrics!.reaChargeLowerBound as number) > 33_554_432);
    assert.equal((r.facts.exports as unknown[]).length, 200);
  });
});

test('malformed WASM: over-long LEB, impossible section, bad order; agree with V8 rejection', async () => {
  for (const [f, rule] of [['bad-leb.wasm', 'wasm-malformed'], ['impossible-section.wasm', 'wasm-malformed'], ['bad-order.wasm', 'wasm-section-order']] as const) {
    const r = await analyze(fx('malformed', f), f);
    assert.equal(r.status, 'partial', f);
    assert.ok(byRule(r.findings, rule), f);
    assert.equal(WebAssembly.validate(readFileSync(fx('malformed', f))), false, f);
  }
});

test('WASM with huge declared counts does not allocate by count', async () => {
  await withTemp(async (d) => {
    const body = [0xff, 0xff, 0xff, 0xff, 0x0f]; // export count 2^32-1 in a 5-byte section
    writeFileSync(join(d, 'c.wasm'), Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 7, body.length, ...body]));
    const r = await analyze(join(d, 'c.wasm'), 'c.wasm');
    assert.equal(r.status, 'partial');
  });
});

test('SQLite helpers: function names skip strings/comments; generated expressions extracted', () => {
  assert.deepEqual(sqlFunctionNames("upper(name) || 'lower(x)' /* evil(1) */ || app_fn(\"col(\")"), ['app_fn', 'upper']);
  assert.deepEqual(generatedExpressions('CREATE TABLE t(a, b TEXT GENERATED ALWAYS AS (f(a, (1))) VIRTUAL, c AS (g(\')\')))'), ['f(a, (1))', "g(')')"]);
});

test('normal SQLite: built-in generated column is not a trap; schema facts only', async () => {
  const r = await analyze(fx('clean', 'normal.sqlite'), 'normal.sqlite');
  assert.equal(r.status, 'complete');
  assert.equal(r.facts.generatedColumns, 1);
  assert.equal(r.facts.views, 1);
  assert.deepEqual(r.findings, []);
});

test('trap SQLite: generated column needing an app function is reported, never evaluated', async () => {
  const r = await analyze(fx('bla-like', 'trap.sqlite'), 'trap.sqlite');
  const f = byRule(r.findings, 'sqlite-generated-column-unknown-function');
  assert.ok(f);
  assert.match(f.observation, /app_unseal/);
  assert.ok(f.evidence[0]!.byteStart !== undefined, 'schema SQL located by byte range');
  assert.ok(byRule(r.findings, 'agent-directed-instruction'), 'comment inside CREATE TABLE is scanned');
  assert.equal(r.suggestedActions![0]!.operation, 'inspect_sqlite_database');
});

test('empty, many-table, malformed SQLite', async () => {
  const e = await analyze(fx('clean', 'empty.sqlite'), 'empty.sqlite');
  assert.equal(e.status, 'complete');
  assert.equal(e.facts.tables, 0);
  const m = await analyze(fx('clean', 'many.sqlite'), 'many.sqlite');
  assert.equal(m.facts.tables, 300);
  for (const f of ['bad-header.sqlite', 'truncated.sqlite']) {
    const r = await analyze(fx('malformed', f), f);
    assert.equal(r.status, 'partial', f);
    assert.ok(byRule(r.findings, 'sqlite-header-inconsistent'), f);
  }
});

test('SQLite inspection leaves no journal/WAL files next to fixtures', () => {
  for (const d of ['clean', 'bla-like', 'malformed']) {
    assert.deepEqual(readdirSync(fx(d)).filter((n) => /-(wal|shm|journal)$/.test(n)), []);
  }
});

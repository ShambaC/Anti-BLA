import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Budget } from '../../src/core/budgets.js';
import { readRange, sha256Bytes, sha256File, walk } from '../../src/core/files.js';
import { makeFinding, preview, redact } from '../../src/core/findings.js';
import { findDuplicateKeys } from '../../src/core/json-dupes.js';
import { aggregateStatus, attribution } from '../../src/core/classification.js';
import { detectFormat } from '../../src/formats/detect.js';
import { fx, withTemp } from '../helpers.js';

test('budget rejects invalid caps and enforces per-file/total allowances', () => {
  assert.throws(() => new Budget({ maxFiles: 0 }));
  assert.throws(() => new Budget({ maxFileBytes: 1.5 }));
  const b = new Budget({ maxFileBytes: 100, maxTotalBytes: 150 });
  assert.equal(b.readAllowance(1000), 100);
  b.chargeRead(100);
  assert.equal(b.readAllowance(1000), 50);
  b.chargeRead(50);
  assert.equal(b.readAllowance(10), 0);
});

test('budget deadline uses injected clock', () => {
  let t = 0;
  const b = new Budget({ maxTimeMs: 10 }, () => t);
  assert.equal(b.timedOut(), false);
  t = 11;
  assert.equal(b.timedOut(), true);
});

test('sha256 of file equals sha256 of bytes; known empty digest', async () => {
  assert.equal(sha256Bytes(Buffer.alloc(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  await withTemp(async (d) => {
    writeFileSync(join(d, 'a'), 'abc');
    assert.equal(await sha256File(join(d, 'a')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

test('readRange clamps to EOF and rejects bad ranges', async () => {
  await withTemp(async (d) => {
    const p = join(d, 'f');
    writeFileSync(p, '0123456789');
    assert.equal((await readRange(p, 8, 100)).toString(), '89');
    assert.equal((await readRange(p, 50, 10)).length, 0);
    await assert.rejects(readRange(p, -1, 1));
    await assert.rejects(readRange(p, 0, Number.MAX_SAFE_INTEGER + 2));
  });
});

test('walk: stable order, caps, depth, symlink escape refused', async () => {
  await withTemp(async (d) => {
    const root = join(d, 'root');
    mkdirSync(join(root, 'b', 'deep', 'deeper'), { recursive: true });
    writeFileSync(join(root, 'z.txt'), 'z');
    writeFileSync(join(root, 'a.txt'), 'a');
    writeFileSync(join(root, 'b', 'm.txt'), 'm');
    writeFileSync(join(root, 'b', 'deep', 'deeper', 'x.txt'), 'x');
    writeFileSync(join(d, 'outside.txt'), 'secret');
    let linked = true;
    try { symlinkSync(join(d, 'outside.txt'), join(root, 'link-out.txt')); } catch { linked = false; }
    const r = await walk(root, new Budget({ maxDepth: 2 }));
    assert.deepEqual(r.files.map((f) => f.logicalPath), ['a.txt', 'b/m.txt', 'z.txt']);
    assert.ok(r.excluded.some((e) => e.path === 'b/deep/deeper' && /max depth/.test(e.reason)));
    if (linked) assert.ok(r.excluded.some((e) => e.path === 'link-out.txt' && /outside/.test(e.reason)));
    const capped = await walk(root, new Budget({ maxFiles: 1 }));
    assert.equal(capped.files.length, 1);
    assert.ok(capped.excluded.some((e) => /max files/.test(e.reason)));
  });
});

test('format detection: magic wins over extension; ambiguous formats are not high confidence', () => {
  const wasm = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
  const d = detectFormat(wasm, 'lib.js');
  assert.equal(d.format, 'wasm');
  assert.ok(d.notes.some((n) => /disagrees/.test(n)));
  assert.equal(detectFormat(Buffer.from('SQLite format 3\0' + 'x'.repeat(100), 'latin1'), 'x.bin').format, 'sqlite');
  assert.equal(detectFormat(Buffer.from('const a = 1;'), 'a.js').confidence, 'medium');
  assert.equal(detectFormat(Buffer.from('not an archive'), 'a.asar').confidence, 'low');
  assert.equal(detectFormat(Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 'a.png').format, 'elf');
  assert.equal(detectFormat(Buffer.from([1, 2, 0, 4]), 'a.js').format, 'binary');
});

test('redaction and preview never echo credentials, controls or bidi characters', () => {
  const s = redact('key AKIAIOSFODNN7EXAMPLE and Bearer abcdefghijklmnopqrstuvwxyz');
  assert.ok(!s.includes('IOSFODNN7EXAMPLE'));
  assert.ok(s.includes('Bearer [REDACTED'));
  const p = preview('a\u0000b\u202ec\nd' + 'x'.repeat(500), 20);
  assert.ok(!/[\u0000\u202e\n]/.test(p));
  assert.ok(p.length < 40);
});

test('findings require evidence and get stable ids', () => {
  const base = { rule: 'r', classification: 'possible-decoy' as const, title: 't', observation: 'o', interpretation: 'i', confidence: 'low' as const };
  assert.throws(() => makeFinding({ ...base, evidence: [] }));
  const a = makeFinding({ ...base, evidence: [{ kind: 'bytes', byteStart: 1 }] });
  const b = makeFinding({ ...base, evidence: [{ kind: 'bytes', byteStart: 1 }] });
  assert.equal(a.id, b.id);
});

test('duplicate JSON keys are detected with pointers', () => {
  const d = findDuplicateKeys('{"a":1,"b":{"x":1,"x":2},"a":3,"arr":[{"k":1,"k":2}]}');
  assert.deepEqual(d.map((x) => [x.pointer, x.key]), [['/b', 'x'], ['/', 'a'], ['/arr/0', 'k']]);
  assert.equal(findDuplicateKeys('{"a":"{\\"a\\":1}","b":2}').length, 0);
});

test('aggregate status and attribution never claim more than observed', () => {
  assert.equal(aggregateStatus(['complete', 'complete'], false), 'complete');
  assert.equal(aggregateStatus(['complete'], true), 'partial');
  assert.equal(aggregateStatus(['failed', 'complete'], false), 'partial');
  assert.equal(aggregateStatus([], true), 'failed');
  const f = (rule: string, confidence: 'low' | 'medium' | 'high') => makeFinding({ rule, classification: 'resource-limit', title: rule, observation: '', interpretation: '', confidence, evidence: [{ kind: 'bytes' }] });
  assert.equal(attribution([]).status, 'none-observed');
  assert.equal(attribution([f('js-alias-table', 'low')]).status, 'none-observed');
  assert.equal(attribution([f('js-literal-alternative-explosion', 'high')]).status, 'bla-like-mechanisms');
  assert.equal(attribution([f('bla-marker-string', 'low')]).status, 'bla-markers-observed');
});

test('fixture directory exists', () => {
  assert.ok(fx('clean'));
});

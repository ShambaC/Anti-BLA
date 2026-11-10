import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fx, runCli, withTemp } from '../helpers.js';

test('--version and --help for every command', () => {
  assert.match(runCli(['--version']).stdout, /^\d+\.\d+\.\d+\n$/);
  const h = runCli(['--help']);
  assert.equal(h.code, 0);
  for (const c of ['triage', 'inspect', 'rea-evidence', 'report']) {
    assert.match(h.stdout, new RegExp(c));
    const sub = runCli([c, '--help']);
    assert.equal(sub.code, 0, c);
    assert.match(sub.stdout, new RegExp(`anti-bla ${c}`));
  }
});

test('triage --json emits a valid report on stdout with logs separated', () => {
  const r = runCli(['triage', fx('clean'), '--json']);
  assert.equal(r.code, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.schemaVersion, 'anti-bla-report/v1');
  assert.equal(j.artifacts.length, 10);
});

test('inspect with explicit format and member', () => {
  const r = runCli(['inspect', fx('clean', 'app.asar'), '--format', 'asar', '--member', 'main.js', '--json']);
  assert.equal(r.code, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.artifacts[1].logicalPath, 'app.asar/main.js');
  assert.equal(runCli(['inspect', fx('clean', 'app.asar'), '--format', 'nope']).code, 2);
  assert.equal(runCli(['inspect', fx('clean')]).code, 2, 'directories need triage');
});

test('invalid input: nonzero exit + structured diagnostic', () => {
  const r = runCli(['triage', fx('does-not-exist'), '--json']);
  assert.equal(r.code, 2);
  assert.equal(JSON.parse(r.stdout).error.code, 'not_found');
  assert.equal(runCli(['bogus']).code, 2);
  assert.equal(runCli(['triage', fx('clean'), '--max-files', '0']).code, 2);
  assert.equal(runCli(['triage', fx('clean'), '--unknown-flag']).code, 2);
  const t = runCli(['rea-evidence', fx('malformed', 'rea-truncated.json'), '--json']);
  assert.equal(t.code, 1, 'failed analysis exits 1');
  assert.equal(JSON.parse(t.stdout).analysisStatus, 'failed');
});

test('output: atomic write, refuses overwrite without --force, refuses inside analyzed input', async () => {
  await withTemp(async (d) => {
    const out = join(d, 'r.json');
    assert.equal(runCli(['triage', fx('clean', 'notes.txt'), '--output', out]).code, 0);
    assert.ok(existsSync(out));
    const again = runCli(['triage', fx('clean', 'notes.txt'), '--output', out, '--json']);
    assert.equal(again.code, 2);
    assert.equal(JSON.parse(again.stdout).error.code, 'output_exists');
    assert.equal(runCli(['triage', fx('clean', 'notes.txt'), '--output', out, '--force']).code, 0);
    const inside = runCli(['triage', fx('clean'), '--output', fx('clean', 'evil.json'), '--json']);
    assert.equal(inside.code, 2);
    assert.equal(JSON.parse(inside.stdout).error.code, 'unsafe_output');
    assert.equal(existsSync(fx('clean', 'evil.json')), false);
    // report renders without reopening targets
    const md = join(d, 'r.md');
    assert.equal(runCli(['report', out, '--format', 'markdown', '--output', md]).code, 0);
    assert.match(readFileSync(md, 'utf8'), /# Anti-BLA report \(triage\)/);
    assert.equal(runCli(['report', out, '--output', out]).code, 2, 'cannot overwrite its own input');
    writeFileSync(join(d, 'bad.json'), '{"schemaVersion":"x"}');
    assert.equal(runCli(['report', join(d, 'bad.json')]).code, 2);
  });
});

test('--redact-paths removes absolute paths from artifact identities', () => {
  const j = JSON.parse(runCli(['inspect', fx('clean', 'notes.txt'), '--json', '--redact-paths']).stdout);
  assert.equal(j.artifacts[0].path, '<redacted>/notes.txt');
});

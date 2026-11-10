// BLA-vs-Anti-BLA showcase (reproducible part).
//   npm install --no-save bla-agents@3.2.1   (BLA is never a dependency of anti-bla)
//   npm run bench:bla                        (optional args: <bla dist/cli.js> <work dir>)
// Builds an owned clean corpus, hardens it with BLA (bankrupt, fixed seed), runs Anti-BLA on both sets and
// writes benchmarks/results/bla-showcase-latest.json. REA runs are recorded separately (see README).
// Only `node <bla cli>` and `node <anti-bla cli>` are spawned, with argument arrays; hardened output is never executed.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildAsar, sqliteFixture, wasmMinimal } from '../scripts/generate-fixtures.js';
import type { AntiBlaReport } from '../src/core/types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(ROOT, 'dist', 'src', 'cli.js');
const sha = (p: string) => createHash('sha256').update(readFileSync(p)).digest('hex');

const LICENSE_JS = `// Acme Notes license gate (owned sample).
export const PRODUCT = 'Acme Notes';
export function checkLicense(key) {
  if (typeof key !== 'string' || key.length !== 16) return false;
  if (!key.startsWith('AB')) return false;
  let sum = 0;
  for (const ch of key) sum += ch.charCodeAt(0);
  return sum % 7 === 3;
}
export function tierFor(key) {
  return checkLicense(key) ? (key[2] === 'P' ? 'pro' : 'basic') : 'free';
}
`;

export async function buildCorpus(dir: string): Promise<void> {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'license.js'), LICENSE_JS);
  writeFileSync(join(dir, 'app.asar'), buildAsar([
    { path: 'package.json', content: '{"name":"acme-notes","version":"1.0.0","main":"main.js"}' },
    { path: 'main.js', content: "const { app, ipcMain } = require('electron');\nipcMain.handle('notes:quota', () => 42);\napp.whenReady().then(() => console.log('ready'));\n" },
    { path: 'preload.js', content: "const { contextBridge, ipcRenderer } = require('electron');\ncontextBridge.exposeInMainWorld('notes', { quota: () => ipcRenderer.invoke('notes:quota') });\n" },
  ]));
  writeFileSync(join(dir, 'module.wasm'), wasmMinimal());
  const db = join(dir, 'licenses.sqlite');
  await sqliteFixture(db, 'empty');
  const { DatabaseSync } = await import('node:sqlite');
  const d = new DatabaseSync(db);
  d.exec(`CREATE TABLE licenses(id INTEGER PRIMARY KEY, license_key TEXT NOT NULL, tier TEXT NOT NULL);
          INSERT INTO licenses(license_key, tier) VALUES ('ABP0000000000003','pro'), ('AB00000000000000','basic');`);
  d.close();
}

function triage(dir: string): AntiBlaReport {
  const p = spawnSync(process.execPath, [CLI, 'triage', dir, '--json'], { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  return JSON.parse(p.stdout) as AntiBlaReport;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const blaCli = process.argv[2] ?? join(ROOT, 'node_modules', 'bla-agents', 'dist', 'cli.js');
  if (!existsSync(blaCli)) { console.error(`BLA CLI not found at ${blaCli}. Run: npm install --no-save bla-agents@3.2.1`); process.exit(2); }
  const work = process.argv[3] ? resolve(process.argv[3]) : mkdtempSync(join(tmpdir(), 'anti-bla-showcase-'));
  const clean = join(work, 'clean');
  const hard = join(work, 'hardened');
  await buildCorpus(clean);
  mkdirSync(hard, { recursive: true });
  const blaVersion = spawnSync(process.execPath, [blaCli, '--version'], { encoding: 'utf8' }).stdout.replace(/\x1b\[[0-9;]*m/g, '').trim();
  const files = ['license.js', 'app.asar', 'module.wasm', 'licenses.sqlite'];
  for (const f of files) {
    const r = spawnSync(process.execPath, [blaCli, 'protect', join(clean, f), '-o', join(hard, f), '--intensity', 'bankrupt', '--seed', 'anti-bla-showcase'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) { console.error(`bla protect ${f} failed: ${r.stderr.slice(0, 500)}`); process.exit(1); }
  }
  const t0 = performance.now();
  const before = triage(clean);
  const after = triage(hard);
  const ms = Math.round(performance.now() - t0);
  const rows = files.map((f) => {
    const fs = after.findings.filter((x) => x.evidence[0]?.logicalPath === f);
    const folded = fs.find((x) => x.rule === 'js-folded-strings');
    return {
      target: f,
      cleanBytes: statSync(join(clean, f)).size,
      hardenedBytes: statSync(join(hard, f)).size,
      cleanSha256: sha(join(clean, f)),
      hardenedSha256: sha(join(hard, f)),
      cleanMediumOrHighFindings: before.findings.filter((x) => x.evidence[0]?.logicalPath === f && x.confidence !== 'low').map((x) => x.rule),
      hardenedRules: [...new Set(fs.filter((x) => x.confidence !== 'low').map((x) => x.rule))].sort(),
      decodedStrings: folded?.evidence.map((e) => e.note) ?? [],
      facts: Object.fromEntries(Object.entries(after.artifacts.find((a) => a.logicalPath === f)?.facts ?? {}).filter(([k]) => ['headerBytes', 'functions', 'exportCount', 'tableNames', 'generatedColumns', 'nodes'].includes(k))),
    };
  });
  const result = { schemaVersion: 'anti-bla-bla-showcase/v1', ranAt: new Date().toISOString(), blaVersion, node: process.version, antiBlaWallMs: ms, attributionClean: before.attribution.status, attributionHardened: after.attribution.status, rows };
  writeFileSync(join(ROOT, 'benchmarks', 'results', 'bla-showcase-latest.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ blaVersion, antiBlaWallMs: ms, rows: rows.map((r) => ({ t: r.target, size: `${r.cleanBytes} -> ${r.hardenedBytes}`, clean: r.cleanMediumOrHighFindings.length, rules: r.hardenedRules.length, decoded: r.decodedStrings.length })) }, null, 1));
}

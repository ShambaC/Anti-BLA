import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Budget, type BudgetLimits } from '../src/core/budgets.js';
import { analyzePath } from '../src/core/pipeline.js';
import { JsWorkerHost } from '../src/formats/javascript.js';
import type { AnalyzerResult, Finding } from '../src/core/types.js';

// dist/tests/helpers.js -> repo root
export const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..');
export const FIX = join(ROOT, 'tests', 'fixtures');
export const CLI = join(ROOT, 'dist', 'src', 'cli.js');
export const fx = (...p: string[]) => join(FIX, ...p);

export function expectedHashes(): Record<string, string> {
  return JSON.parse(readFileSync(fx('expected', 'hashes.json'), 'utf8')) as Record<string, string>;
}

export function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

export function withTemp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'anti-bla-test-'));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const host = new JsWorkerHost(512);
export async function analyze(path: string, logical: string, limits: Partial<BudgetLimits> = {}, opts: { formatOverride?: string; member?: string } = {}): Promise<AnalyzerResult & { sha256: string }> {
  const r = await analyzePath(path, logical, new Budget(limits), host, opts);
  if ('excluded' in r) throw new Error(`excluded: ${r.excluded}`);
  return Object.assign(r.result, { sha256: r.identity.sha256 });
}
export const closeHost = () => host.close();

export const rules = (fs: Finding[]) => fs.map((f) => f.rule).sort();
export const byRule = (fs: Finding[], rule: string) => fs.find((f) => f.rule === rule);

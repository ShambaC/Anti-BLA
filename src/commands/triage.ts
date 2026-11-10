import { access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Budget } from '../core/budgets.js';
import { walk } from '../core/files.js';
import { analyzePath, type PipelineResult } from '../core/pipeline.js';
import type { AntiBlaReport } from '../core/types.js';
import { JsWorkerHost } from '../formats/javascript.js';
import { assemble, emptyCollected, UsageError, type Collected } from './assemble.js';

export function addResult(c: Collected, r: PipelineResult): void {
  c.artifacts.push(r.identity);
  c.statuses.push(r.result.status);
  c.examined.push(r.identity.logicalPath);
  c.findings.push(...r.result.findings);
  c.actions.push(...(r.result.suggestedActions ?? []));
  c.limitations.push(...r.result.limitations.map((l) => `${r.identity.logicalPath}: ${l}`));
  c.unknowns.push(...r.result.unknowns);
}

export async function runTriage(target: string, budget: Budget, opts: { redactPaths?: boolean } = {}): Promise<AntiBlaReport> {
  const root = resolve(target);
  try { await access(root); } catch { throw new UsageError(`Path not found or not readable: ${root}`, 'not_found'); }
  const { files, excluded } = await walk(root, budget);
  const byLogical = new Map(files.map((f) => [f.logicalPath, f.path]));
  const c = emptyCollected();
  c.excluded.push(...excluded);
  const host = new JsWorkerHost(budget.limits.jsWorkerHeapMb);
  try {
    for (const f of files) {
      if (budget.timedOut()) {
        c.excluded.push({ path: f.logicalPath, reason: 'time budget exhausted before analysis' });
        budget.markTruncated('time budget exhausted');
        continue;
      }
      const r = await analyzePath(f.path, f.logicalPath, budget, host, { sibling: (lp) => byLogical.get(lp) });
      if ('excluded' in r) c.excluded.push({ path: f.logicalPath, reason: r.excluded });
      else addResult(c, r);
    }
  } finally {
    await host.close();
  }
  if (files.length === 0 && excluded.length === 0) c.limitations.push('No regular files found under the selected path.');
  return assemble('triage', c, budget, opts);
}

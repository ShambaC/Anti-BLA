import { realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { aggregateStatus, attribution } from '../core/classification.js';
import { capFindings } from '../core/findings.js';
import { isInside } from '../core/files.js';
import type { Budget } from '../core/budgets.js';
import { REPORT_SCHEMA_VERSION, type AnalysisStatus, type AntiBlaReport, type ArtifactIdentity, type Finding, type ReaSummary, type SuggestedAction } from '../core/types.js';

export const TOOL_VERSION = '0.1.0';

export class UsageError extends Error {
  constructor(message: string, readonly code = 'invalid_input') { super(message); }
}

export interface Collected {
  artifacts: ArtifactIdentity[];
  statuses: AnalysisStatus[];
  findings: Finding[];
  actions: SuggestedAction[];
  examined: string[];
  excluded: { path: string; reason: string }[];
  limitations: string[];
  unknowns: string[];
}

export const emptyCollected = (): Collected => ({ artifacts: [], statuses: [], findings: [], actions: [], examined: [], excluded: [], limitations: [], unknowns: [] });

const evKey = (f: Finding) => {
  const e = f.evidence[0]!;
  return [e.logicalPath ?? '', String(e.byteStart ?? -1).padStart(16, '0'), f.rule, f.id].join('\u0000');
};

export function assemble(command: AntiBlaReport['command'], c: Collected, budget: Budget, opts: { redactPaths?: boolean; rea?: ReaSummary } = {}): AntiBlaReport {
  const { kept, dropped } = capFindings(c.findings, budget.limits.maxFindings);
  const limitations = [...c.limitations];
  if (dropped) { limitations.push(`${dropped} finding(s) dropped by --max-findings ${budget.limits.maxFindings} (lowest confidence first).`); budget.markTruncated('max findings reached'); }
  for (const r of budget.reasons) limitations.push(`Budget: ${r}.`);
  const findings = [...kept].sort((a, b) => (evKey(a) < evKey(b) ? -1 : 1));
  const seen = new Set<string>();
  const actions = c.actions.filter((a) => { const k = JSON.stringify([a.kind, a.title, a.operation]); if (seen.has(k)) return false; seen.add(k); return true; });
  const uniq = (xs: string[]) => [...new Set(xs)];
  const report: AntiBlaReport = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    command,
    analysisStatus: aggregateStatus(c.statuses, c.excluded.length > 0 || budget.truncated),
    analyzedAt: new Date().toISOString(),
    toolVersion: TOOL_VERSION,
    artifacts: c.artifacts.map((a) => (opts.redactPaths ? { ...a, path: `<redacted>/${a.logicalPath}` } : a)),
    findings,
    suggestedActions: actions,
    coverage: { examined: c.examined, excluded: c.excluded },
    limitations: uniq(limitations),
    unknowns: uniq(c.unknowns),
    attribution: attribution(findings),
    budgets: { elapsedMs: budget.elapsedMs(), bytesRead: budget.bytesRead, bytesHashed: budget.bytesHashed, truncated: budget.truncated, limits: { ...budget.limits } },
  };
  if (opts.rea) report.rea = opts.rea;
  return report;
}

/** Atomic write to an explicit destination; refuses overwrite without --force and refuses paths inside analyzed inputs. */
export async function writeOutput(outPath: string, content: string, force: boolean, protectedPaths: string[]): Promise<void> {
  const out = resolve(outPath);
  // Compare real paths (symlinks/junctions/8.3 names resolved) and, on Windows/macOS, case-insensitively.
  let realOut = out;
  try { realOut = join(await realpath(dirname(out)), basename(out)); } catch { /* parent missing: writeFile will fail */ }
  const fold = (p: string) => (process.platform === 'win32' || process.platform === 'darwin' ? p.toLowerCase() : p);
  let outStat: Awaited<ReturnType<typeof stat>> | null = null;
  try { outStat = await stat(out, { bigint: true }); } catch { /* absent */ }
  for (const p of protectedPaths) {
    let abs = resolve(p);
    try { abs = await realpath(abs); } catch { /* gone */ }
    let st: Awaited<ReturnType<typeof stat>> | null = null;
    try { st = await stat(abs, { bigint: true }); } catch { /* gone */ }
    const sameFile = !!(st && outStat && st.ino !== 0n && st.ino === outStat.ino && st.dev === outStat.dev);
    if (sameFile || fold(realOut) === fold(abs) || (st?.isDirectory() && isInside(fold(abs), fold(realOut)))) {
      throw new UsageError(`Refusing to write output inside or onto an analyzed input: ${out}`, 'unsafe_output');
    }
  }
  let exists = false;
  try { await stat(out); exists = true; } catch { /* absent */ }
  if (exists && !force) throw new UsageError(`Output exists: ${out} (use --force to overwrite)`, 'output_exists');
  const tmp = `${out}.anti-bla-${process.pid}.tmp`;
  try {
    await writeFile(tmp, content, { flag: 'wx' });
    await rename(tmp, out);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

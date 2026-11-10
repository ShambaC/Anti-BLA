import { basename, resolve } from 'node:path';
import { stat } from 'node:fs/promises';
import { Budget } from '../core/budgets.js';
import { analyzeBuffer, analyzePath, SUPPORTED_FORMATS } from '../core/pipeline.js';
import { sha256Bytes } from '../core/files.js';
import type { AnalyzerResult, AntiBlaReport } from '../core/types.js';
import { detectFormat } from '../formats/detect.js';
import { JsWorkerHost } from '../formats/javascript.js';
import { assemble, emptyCollected, UsageError } from './assemble.js';
import { addResult } from './triage.js';

export const INSPECT_FORMATS = ['auto', ...SUPPORTED_FORMATS, 'generic'];

export async function runInspect(target: string, budget: Budget, opts: { format?: string; member?: string; redactPaths?: boolean } = {}): Promise<AntiBlaReport> {
  const path = resolve(target);
  let st;
  try { st = await stat(path); } catch { throw new UsageError(`File not found or not readable: ${path}`, 'not_found'); }
  if (!st.isFile()) throw new UsageError(`inspect needs a regular file (use triage for directories): ${path}`);
  if (opts.format && !INSPECT_FORMATS.includes(opts.format)) throw new UsageError(`Unknown --format ${opts.format}; expected one of ${INSPECT_FORMATS.join(', ')}`);
  const c = emptyCollected();
  const host = new JsWorkerHost(budget.limits.jsWorkerHeapMb);
  try {
    const pipeOpts: { formatOverride?: string; member?: string } = {};
    if (opts.format) pipeOpts.formatOverride = opts.format;
    if (opts.member !== undefined) pipeOpts.member = opts.member;
    const r = await analyzePath(path, basename(path), budget, host, pipeOpts);
    if ('excluded' in r) {
      c.excluded.push({ path: basename(path), reason: r.excluded });
    } else {
      addResult(c, r);
      if (opts.member !== undefined && r.identity.detectedFormat !== 'asar') c.limitations.push('--member applies only to ASAR archives; ignored.');
      const sel = (r.result as AnalyzerResult & { selectedMember?: { logicalPath: string; bytes: Buffer } }).selectedMember;
      if (sel) {
        // Analyze the selected member in memory; it is never written to disk.
        const det = detectFormat(sel.bytes, sel.logicalPath);
        // Analyzers for these formats re-read ctx.path; in-memory members get the generic byte scan instead.
        if (['asar', 'pe', 'elf', 'macho', 'macho-fat-or-java-class'].includes(det.format)) {
          det.notes.push(`nested ${det.format} member analyzed with generic byte scan only`);
          det.format = 'binary';
        }
        const sha = sha256Bytes(sel.bytes);
        const res = await analyzeBuffer({ path, logicalPath: sel.logicalPath, sha256: sha, sizeBytes: sel.bytes.length, bytes: sel.bytes, truncated: false, budget }, det.format, host);
        addResult(c, { identity: { path: `${path}#${sel.logicalPath}`, logicalPath: sel.logicalPath, sha256: sha, sizeBytes: sel.bytes.length, detectedFormat: det.format, formatConfidence: det.confidence, analysisStatus: res.status }, result: res, detectionNotes: det.notes });
      }
    }
  } finally {
    await host.close();
  }
  return assemble('inspect', c, budget, opts);
}

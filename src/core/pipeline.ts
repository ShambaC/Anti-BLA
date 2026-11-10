// Per-artifact pipeline shared by `triage` and `inspect`: fingerprint -> detect -> analyze -> verify unchanged.
import { makeFinding } from './findings.js';
import { changedSince, fingerprint } from './fingerprint.js';
import { byteRef } from './provenance.js';
import type { Budget } from './budgets.js';
import type { AnalyzeContext, AnalyzerResult, ArtifactIdentity } from './types.js';
import { detectFormat } from '../formats/detect.js';
import { analyzeJavaScript, analyzeSourceMapWithBundle, type JsWorkerHost } from '../formats/javascript.js';
import { analyzeAsar } from '../formats/asar.js';
import { analyzeWasm } from '../formats/wasm.js';
import { analyzeSqlite } from '../formats/sqlite.js';
import { analyzeGeneric } from '../formats/generic.js';

export interface PipelineOptions {
  formatOverride?: string;
  sibling?: (logicalPath: string) => string | undefined;
  member?: string;
}

export interface PipelineResult {
  identity: ArtifactIdentity;
  result: AnalyzerResult;
  detectionNotes: string[];
}

export const SUPPORTED_FORMATS = ['javascript', 'typescript', 'source-map', 'asar', 'wasm', 'sqlite'];

export async function analyzeBuffer(ctx: AnalyzeContext, format: string, host: JsWorkerHost): Promise<AnalyzerResult> {
  try {
    switch (format) {
      case 'javascript':
      case 'typescript':
        return await analyzeJavaScript(ctx, host, format);
      case 'source-map':
        return await analyzeSourceMapWithBundle(ctx);
      case 'asar':
        return await analyzeAsar(ctx);
      case 'wasm':
        return await analyzeWasm(ctx);
      case 'sqlite':
        return await analyzeSqlite(ctx);
      default:
        return await analyzeGeneric(ctx, format);
    }
  } catch (e) {
    // A crashing analyzer yields a typed partial result; it never aborts the batch.
    return {
      status: 'failed',
      format,
      formatConfidence: 'low',
      findings: [
        makeFinding({
          rule: 'analyzer-error',
          classification: 'analysis-limitation',
          title: `${format} analyzer error`,
          observation: `${(e as Error).name}: ${(e as Error).message}`.slice(0, 300),
          interpretation: 'Anti-BLA could not finish this artifact. This is a tool limitation, not evidence about the artifact.',
          confidence: 'high',
          evidence: [byteRef(ctx.sha256, ctx.logicalPath, 0, ctx.bytes.length, 'inspected prefix')],
        }),
      ],
      limitations: ['Analyzer raised an unexpected error.'],
      unknowns: [`${ctx.logicalPath}: all format-specific structure.`],
      facts: {},
    };
  }
}

export async function analyzePath(path: string, logicalPath: string, budget: Budget, host: JsWorkerHost, opts: PipelineOptions = {}): Promise<PipelineResult | { excluded: string }> {
  let fp;
  try {
    fp = await fingerprint(path, budget);
  } catch (e) {
    // Locked, deleted or unreadable mid-scan: exclude this file, keep the batch going.
    return { excluded: `unreadable: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message.slice(0, 80)}` };
  }
  if (!fp) {
    budget.markTruncated('time budget exhausted while hashing');
    return { excluded: 'time budget exhausted while hashing' };
  }
  const det = detectFormat(fp.head, logicalPath);
  const format = opts.formatOverride && opts.formatOverride !== 'auto' ? opts.formatOverride : det.format;
  if (fp.truncated) budget.markTruncated('file read truncated by byte budget');
  const ctx: AnalyzeContext = { path, logicalPath, sha256: fp.sha256, sizeBytes: fp.size, bytes: fp.bytes, truncated: fp.truncated, budget };
  if (opts.sibling) ctx.sibling = opts.sibling;
  if (opts.member !== undefined) ctx.member = opts.member;
  const result = await analyzeBuffer(ctx, format, host);
  if (det.notes.length) result.limitations.push(...det.notes.map((n) => `Format detection: ${n}`));
  if (await changedSince(path, fp.before)) {
    result.status = result.status === 'complete' ? 'partial' : result.status;
    result.limitations.push('File metadata changed during the scan; results may mix two versions.');
  }
  return {
    identity: {
      path,
      logicalPath,
      sha256: fp.sha256,
      sizeBytes: fp.size,
      detectedFormat: format,
      formatConfidence: opts.formatOverride && opts.formatOverride !== 'auto' ? 'high' : det.confidence,
      analysisStatus: result.status,
    },
    result,
    detectionNotes: det.notes,
  };
}

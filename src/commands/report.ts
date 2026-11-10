import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { AntiBlaReport } from '../core/types.js';
import { toJson, validateReport } from '../reports/json.js';
import { toMarkdown } from '../reports/markdown.js';
import { UsageError } from './assemble.js';

const MAX_REPORT_BYTES = 256 * 1024 * 1024;

/** Re-render a stored Anti-BLA report. Never reopens any analyzed target. */
export async function runReport(input: string, format: string): Promise<string> {
  const path = resolve(input);
  let size: number;
  try { size = (await stat(path)).size; } catch { throw new UsageError(`Report not found: ${path}`, 'not_found'); }
  if (size > MAX_REPORT_BYTES) throw new UsageError(`Report larger than ${MAX_REPORT_BYTES} bytes`);
  let parsed: unknown;
  try { parsed = JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, '')); } catch (e) { throw new UsageError(`Report is not valid JSON: ${(e as Error).message}`, 'invalid_report'); }
  const errs = validateReport(parsed);
  if (errs.length) throw new UsageError(`Not an anti-bla-report/v1 document: ${errs.join('; ')}`, 'invalid_report');
  if (format === 'markdown' || format === 'md') return toMarkdown(parsed as AntiBlaReport);
  if (format === 'json') return toJson(parsed as AntiBlaReport);
  throw new UsageError(`Unknown --format ${format}; expected markdown or json`);
}

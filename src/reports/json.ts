import { REPORT_SCHEMA_VERSION, type AntiBlaReport } from '../core/types.js';

export function toJson(report: AntiBlaReport): string {
  return JSON.stringify(report, null, 2) + '\n';
}

/** Minimal structural validation of a stored report before rendering it (it is untrusted input too). */
export function validateReport(v: unknown): string[] {
  const errs: string[] = [];
  const o = v as Partial<AntiBlaReport>;
  if (!o || typeof o !== 'object') return ['not an object'];
  if (o.schemaVersion !== REPORT_SCHEMA_VERSION) errs.push(`schemaVersion must be ${REPORT_SCHEMA_VERSION}`);
  if (!['complete', 'partial', 'failed', 'unsupported'].includes(String(o.analysisStatus))) errs.push('invalid analysisStatus');
  for (const k of ['artifacts', 'findings', 'suggestedActions', 'limitations', 'unknowns'] as const) if (!Array.isArray(o[k])) errs.push(`${k} must be an array`);
  if (!o.coverage || !Array.isArray(o.coverage.examined) || !Array.isArray(o.coverage.excluded)) errs.push('coverage.examined/excluded must be arrays');
  if (!o.budgets || typeof o.budgets.truncated !== 'boolean') errs.push('budgets.truncated must be boolean');
  if (Array.isArray(o.findings)) {
    o.findings.forEach((f, i) => {
      if (!f || typeof f.id !== 'string' || !Array.isArray(f.evidence) || f.evidence.length === 0) errs.push(`findings[${i}] lacks id or evidence`);
    });
  }
  return errs;
}

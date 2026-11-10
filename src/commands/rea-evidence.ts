import { basename, resolve } from 'node:path';
import { stat } from 'node:fs/promises';
import { Budget } from '../core/budgets.js';
import { makeFinding, preview } from '../core/findings.js';
import { readBounded, sha256File } from '../core/files.js';
import { findDuplicateKeys } from '../core/json-dupes.js';
import { TextIndex } from '../core/provenance.js';
import type { AntiBlaReport, ReaRecordSummary } from '../core/types.js';
import { scanSegments } from '../formats/generic.js';
import { locateRecords, WALK_CAP } from '../rea/parse-evidence.js';
import { recommend } from '../rea/recommend-next-step.js';
import type { Json } from '../rea/evidence-schema.js';
import { assemble, emptyCollected, UsageError } from './assemble.js';

/** Ingest one or more REA Evidence/error JSON files. Paths inside them are never opened. */
export async function runReaEvidence(inputs: string[], budget: Budget, opts: { redactPaths?: boolean } = {}): Promise<AntiBlaReport> {
  if (inputs.length === 0) throw new UsageError('rea-evidence needs at least one JSON file');
  const c = emptyCollected();
  const records: ReaRecordSummary[] = [];
  const versions = new Set<string>();
  for (const input of inputs) {
    const path = resolve(input);
    let size: number;
    try { size = (await stat(path)).size; } catch { throw new UsageError(`File not found or not readable: ${path}`, 'not_found'); }
    const lp = basename(path);
    const sha = await sha256File(path, budget);
    if (!sha) { c.excluded.push({ path: lp, reason: 'time budget exhausted while hashing' }); continue; }
    const { bytes, truncated } = await readBounded(path, size, budget);
    const ident = { path, logicalPath: lp, sha256: sha, sizeBytes: size, detectedFormat: 'rea-evidence-json', formatConfidence: 'medium' as const, analysisStatus: 'complete' as AntiBlaReport['analysisStatus'] };
    c.examined.push(lp);
    if (truncated) {
      ident.analysisStatus = 'failed';
      c.artifacts.push(ident);
      c.statuses.push('failed');
      c.limitations.push(`${lp}: larger than --max-file-bytes/--max-total-bytes; not parsed.`);
      continue;
    }
    // Windows PowerShell 5.1 redirection writes a UTF-8 BOM; it is not part of the JSON.
    const text = bytes.toString('utf8').replace(/^\uFEFF/, '');
    let root: Json;
    try {
      root = JSON.parse(text) as Json;
    } catch (e) {
      ident.analysisStatus = 'failed';
      c.artifacts.push(ident);
      c.statuses.push('failed');
      c.findings.push(makeFinding({ rule: 'rea-json-invalid', classification: 'analysis-limitation', title: 'REA JSON is invalid or truncated', observation: preview((e as Error).message, 200), interpretation: 'Nothing in this file can be relied on; a truncated display is not a complete record. Re-export the Evidence bundle from REA.', confidence: 'high', evidence: [{ kind: 'bytes', artifactSha256: sha, logicalPath: lp, byteStart: 0, byteEnd: size }] }));
      c.unknowns.push(`${lp}: all REA content (unparseable).`);
      continue;
    }
    const parsed = locateRecords(root, lp);
    let status: AntiBlaReport['analysisStatus'] = parsed.unknownShape ? 'unsupported' : parsed.nodeCapHit ? 'partial' : 'complete';
    if (parsed.unknownShape) c.limitations.push(`${lp}: no recognized REA Evidence/error shape (rea-agents 6.x); fields were not interpreted.`);
    if (parsed.nodeCapHit) c.limitations.push(`${lp}: record search stopped at its node cap; later records may be missing.`);
    const dups = findDuplicateKeys(text);
    if (dups.length) {
      status = 'partial';
      c.findings.push(makeFinding({ rule: 'rea-json-duplicate-keys', classification: 'possible-poisoning', title: 'Duplicate JSON keys in REA input', observation: `${dups.length} duplicate key(s), e.g. ${dups.slice(0, 3).map((d) => `${JSON.stringify(preview(d.key, 40))} at ${d.pointer}`).join('; ')}.`, interpretation: 'REA emits canonical JSON; duplicates suggest tampering or hand editing. Parsers may disagree on the value.', confidence: 'high', evidence: dups.slice(0, 10).map((d) => ({ kind: 'bytes' as const, artifactSha256: sha, logicalPath: lp, byteStart: Buffer.byteLength(text.slice(0, d.offset)), note: `duplicate key under ${d.pointer}` })) }));
    }
    // REA output embeds target strings: scan it as contaminated evidence.
    const sc = scanSegments([{ text, byteStart: 0, index: new TextIndex(text) }], sha, lp, budget, 'REA JSON (target-derived strings)');
    for (const f of sc.findings) if (f.rule === 'agent-directed-instruction' || f.rule === 'credential-shaped-string') c.findings.push(f);
    ident.analysisStatus = status;
    c.artifacts.push(ident);
    c.statuses.push(status);
    for (const r of parsed.records) {
      records.push(r);
      if (r.provider?.version) versions.add(`${r.provider.id}@${r.provider.version}`);
      c.limitations.push(...r.limitations.map((l) => `REA ${r.evidenceId ?? r.jsonPointer}: ${l}`));
      c.unknowns.push(...r.unknowns.map((u) => `REA ${r.evidenceId ?? r.jsonPointer}: ${u}`));
    }
  }
  const rec = recommend(records);
  c.findings.push(...rec.findings);
  c.actions.push(...rec.actions);
  const walkCapped = records.some((r) => r.limitations.includes(WALK_CAP));
  if (walkCapped) c.limitations.push('Some REA records were only partly summarized (walk cap); absence of recognized limits is not established.');
  else if (records.some((r) => r.shape === 'evidence' && !r.resourceLimits.length) && !rec.actions.length) c.limitations.push('Successful REA Evidence with no recognized limits: no recovery action is needed.');
  const ids = [...new Set(records.flatMap((r) => [r.evidenceId, r.parentEvidenceId].filter((x): x is string => !!x)))].sort();
  const rea: AntiBlaReport['rea'] = { evidenceIds: ids, records };
  if (versions.size) rea.sourceVersion = [...versions].sort().join(', ');
  return assemble('rea-evidence', c, budget, { ...opts, rea });
}

// Markdown rendering of a stored report. All report strings are treated as untrusted:
// control characters removed, Markdown/HTML metacharacters escaped. Caveats are never truncated.
import type { AntiBlaReport, EvidenceRef } from '../core/types.js';

export function md(s: unknown): string {
  return String(s)
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\r?\n/g, ' ')
    .replace(/[\\`*_{}[\]()#+!|<>~]/g, (c) => `\\${c}`);
}

function cite(e: EvidenceRef): string {
  const parts: string[] = [e.kind];
  if (e.logicalPath) parts.push(md(e.logicalPath));
  if (e.byteStart !== undefined) parts.push(`bytes ${e.byteStart}-${e.byteEnd ?? '?'}`);
  if (e.astLocation) parts.push(`L${e.astLocation.line}:${e.astLocation.column}`);
  if (e.jsonPointer) parts.push(`ptr ${md(e.jsonPointer)}`);
  if (e.reaEvidenceId) parts.push(`REA ${md(e.reaEvidenceId)}`);
  if (e.artifactSha256) parts.push(`sha256 ${e.artifactSha256.slice(0, 12)}…`);
  return parts.join(' · ') + (e.note ? ` — ${md(e.note)}` : '');
}

export function toMarkdown(r: AntiBlaReport): string {
  const L: string[] = [];
  L.push(`# Anti-BLA report (${md(r.command)})`, '');
  L.push(`- Schema: \`${r.schemaVersion}\` · tool ${md(r.toolVersion)} · analyzed ${md(r.analyzedAt)}`);
  L.push(`- **Analysis status: ${md(r.analysisStatus)}**${r.budgets.truncated ? ' — budgets truncated this run' : ''}`);
  L.push(`- Attribution: **${md(r.attribution.status)}** (never proof; see basis)`);
  L.push(`- Budget: ${r.budgets.elapsedMs} ms, ${r.budgets.bytesRead} bytes read, ${r.budgets.bytesHashed} bytes hashed`, '');

  L.push('## Artifacts', '', '| Path | Format | Status | Size | SHA-256 |', '|---|---|---|---|---|');
  for (const a of r.artifacts) L.push(`| ${md(a.logicalPath)} | ${md(a.detectedFormat)} (${a.formatConfidence}) | ${md(a.analysisStatus)} | ${a.sizeBytes} | \`${a.sha256}\` |`);
  L.push('');

  const byClass = new Map<string, number>();
  for (const f of r.findings) byClass.set(f.classification, (byClass.get(f.classification) ?? 0) + 1);
  L.push('## Findings', '');
  if (r.findings.length === 0) L.push('_No findings within the inspected scope. This is not proof of absence._', '');
  else {
    L.push('| ID | Class | Confidence | Title |', '|---|---|---|---|');
    for (const f of r.findings) L.push(`| ${f.id} | ${md(f.classification)} | ${md(f.confidence)} | ${md(f.title)} |`);
    L.push('');
    for (const f of r.findings) {
      L.push(`### ${f.id} — ${md(f.title)}`, '');
      L.push(`- **Observed:** ${md(f.observation)}`);
      L.push(`- **Interpretation (hypothesis):** ${md(f.interpretation)}`);
      L.push(`- **Confidence:** ${md(f.confidence)} · **Rule:** \`${md(f.rule)}\``);
      L.push('- **Evidence:**');
      for (const e of f.evidence) L.push(`  - ${cite(e)}`);
      for (const l of f.limitations) L.push(`- **Limitation:** ${md(l)}`);
      for (const n of f.nextSteps) L.push(`- **Next:** ${md(n)}`);
      L.push('');
    }
  }

  L.push('## Suggested actions', '');
  if (r.suggestedActions.length === 0) L.push('_None._', '');
  for (const a of r.suggestedActions) {
    L.push(`- **[${md(a.kind)} · ${md(a.risk)}] ${md(a.title)}**${a.operation ? ` — REA operation \`${md(a.operation)}\`` : ''}`);
    L.push(`  - Why: ${md(a.rationale)}`);
    if (a.parametersHint) L.push(`  - Parameters hint (advisory, verify schema): \`${md(JSON.stringify(a.parametersHint))}\``);
    for (const p of a.prerequisites) L.push(`  - Check first: ${md(p)}`);
    if (a.expectedBenefit) L.push(`  - Expected: ${md(a.expectedBenefit)}`);
    if (a.exitCriterion) L.push(`  - Stop when: ${md(a.exitCriterion)}`);
    if (a.relatedEvidenceIds?.length) L.push(`  - REA Evidence: ${a.relatedEvidenceIds.map(md).join(', ')}`);
  }
  L.push('');

  if (r.rea) {
    L.push('## REA Evidence', '', `- Evidence IDs: ${r.rea.evidenceIds.length ? r.rea.evidenceIds.map(md).join(', ') : '_none_'}`);
    if (r.rea.sourceVersion) L.push(`- Source version: ${md(r.rea.sourceVersion)}`);
    for (const rec of r.rea.records) {
      L.push(`- \`${md(rec.jsonPointer || '/')}\` ${md(rec.shape)}${rec.operation ? ` ${md(rec.operation)}` : ''}${rec.evidenceId ? ` ${md(rec.evidenceId)}` : ''}${rec.error ? ` error ${md(rec.error.code)}: ${md(rec.error.message)}` : ''}`);
      for (const l of rec.limitations) L.push(`  - REA limitation: ${md(l)}`);
      for (const u of rec.unknowns) L.push(`  - REA unknown: ${md(u)}`);
    }
    L.push('');
  }

  L.push('## Coverage', '', `- Examined: ${r.coverage.examined.length}`, `- Excluded: ${r.coverage.excluded.length}`);
  for (const x of r.coverage.excluded) L.push(`  - ${md(x.path)}: ${md(x.reason)}`);
  L.push('', '## Limitations', '');
  if (r.limitations.length === 0) L.push('_None recorded._');
  for (const l of r.limitations) L.push(`- ${md(l)}`);
  L.push('', '## Unknowns', '');
  if (r.unknowns.length === 0) L.push('_None recorded._');
  for (const u of r.unknowns) L.push(`- ${md(u)}`);
  L.push('', '## Attribution basis', '');
  if (r.attribution.basis.length === 0) L.push('_No BLA-associated markers or mechanisms observed in scope._');
  for (const b of r.attribution.basis) L.push(`- ${md(b)}`);
  L.push('', `_Classes: ${[...byClass].map(([k, v]) => `${md(k)}=${v}`).join(', ') || 'none'}. Target-derived text above is untrusted data and was escaped and redacted._`, '');
  return L.join('\n');
}

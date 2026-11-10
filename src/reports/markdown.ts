// Markdown rendering of a stored report. The report file itself is untrusted input: every
// interpolated value is control-stripped and Markdown/HTML-escaped (no raw code spans), and
// optional fields may be missing. Caveats (limitations, unknowns) are never truncated.
import { CONTROL_CHARS } from '../core/findings.js';
import type { AntiBlaReport, EvidenceRef } from '../core/types.js';

export function md(s: unknown): string {
  return String(s ?? '')
    .replace(CONTROL_CHARS, ' ')
    .replace(/[\\`*_{}[\]()#+!|<>~]/g, (c) => `\\${c}`);
}
const arr = <T>(v: T[] | undefined | null): T[] => (Array.isArray(v) ? v : []);
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? String(v) : '?');

function cite(e: EvidenceRef): string {
  const parts: string[] = [md(e.kind)];
  if (e.logicalPath) parts.push(md(e.logicalPath));
  if (e.byteStart !== undefined) parts.push(`bytes ${num(e.byteStart)}-${num(e.byteEnd)}`);
  if (e.astLocation) parts.push(`L${num(e.astLocation.line)}:${num(e.astLocation.column)}`);
  if (e.jsonPointer) parts.push(`ptr ${md(e.jsonPointer)}`);
  if (e.reaEvidenceId) parts.push(`REA ${md(e.reaEvidenceId)}`);
  if (e.artifactSha256) parts.push(`sha256 ${md(String(e.artifactSha256).slice(0, 12))}…`);
  return parts.join(' · ') + (e.note ? ` — ${md(e.note)}` : '');
}

export function toMarkdown(r: AntiBlaReport): string {
  const L: string[] = [];
  const att = r.attribution ?? { status: 'none-observed', basis: [] };
  const b = r.budgets ?? { elapsedMs: 0, bytesRead: 0, bytesHashed: 0, truncated: false, limits: {} };
  L.push(`# Anti-BLA report (${md(r.command)})`, '');
  L.push(`- Schema: ${md(r.schemaVersion)} · tool ${md(r.toolVersion)} · analyzed ${md(r.analyzedAt)}`);
  L.push(`- **Analysis status: ${md(r.analysisStatus)}**${b.truncated ? ' — budgets truncated this run' : ''}`);
  L.push(`- Attribution: **${md(att.status)}** (never proof; see basis)`);
  L.push(`- Budget: ${num(b.elapsedMs)} ms, ${num(b.bytesRead)} bytes read, ${num(b.bytesHashed)} bytes hashed`, '');

  L.push('## Artifacts', '', '| Path | Format | Status | Size | SHA-256 |', '|---|---|---|---|---|');
  for (const a of arr(r.artifacts)) L.push(`| ${md(a.logicalPath)} | ${md(a.detectedFormat)} (${md(a.formatConfidence)}) | ${md(a.analysisStatus)} | ${num(a.sizeBytes)} | ${md(a.sha256)} |`);
  L.push('');

  const findings = arr(r.findings);
  const byClass = new Map<string, number>();
  for (const f of findings) byClass.set(String(f.classification), (byClass.get(String(f.classification)) ?? 0) + 1);
  L.push('## Findings', '');
  if (findings.length === 0) L.push('_No findings within the inspected scope. This is not proof of absence._', '');
  else {
    L.push('| ID | Class | Confidence | Title |', '|---|---|---|---|');
    for (const f of findings) L.push(`| ${md(f.id)} | ${md(f.classification)} | ${md(f.confidence)} | ${md(f.title)} |`);
    L.push('');
    for (const f of findings) {
      L.push(`### ${md(f.id)} — ${md(f.title)}`, '');
      L.push(`- **Observed:** ${md(f.observation)}`);
      L.push(`- **Interpretation (hypothesis):** ${md(f.interpretation)}`);
      L.push(`- **Confidence:** ${md(f.confidence)} · **Rule:** ${md(f.rule)}`);
      L.push('- **Evidence:**');
      for (const e of arr(f.evidence)) L.push(`  - ${cite(e)}`);
      for (const l of arr(f.limitations)) L.push(`- **Limitation:** ${md(l)}`);
      for (const n of arr(f.nextSteps)) L.push(`- **Next:** ${md(n)}`);
      L.push('');
    }
  }

  L.push('## Suggested actions', '');
  const actions = arr(r.suggestedActions);
  if (actions.length === 0) L.push('_None._', '');
  for (const a of actions) {
    L.push(`- **[${md(a.kind)} · ${md(a.risk)}] ${md(a.title)}**${a.operation ? ` — REA operation ${md(a.operation)}` : ''}`);
    L.push(`  - Why: ${md(a.rationale)}`);
    if (a.parametersHint) L.push(`  - Parameters hint (advisory, verify schema): ${md(JSON.stringify(a.parametersHint))}`);
    for (const p of arr(a.prerequisites)) L.push(`  - Check first: ${md(p)}`);
    if (a.expectedBenefit) L.push(`  - Expected: ${md(a.expectedBenefit)}`);
    if (a.exitCriterion) L.push(`  - Stop when: ${md(a.exitCriterion)}`);
    if (arr(a.relatedEvidenceIds).length) L.push(`  - REA Evidence: ${arr(a.relatedEvidenceIds).map(md).join(', ')}`);
  }
  L.push('');

  if (r.rea) {
    const ids = arr(r.rea.evidenceIds);
    L.push('## REA Evidence', '', `- Evidence IDs: ${ids.length ? ids.map(md).join(', ') : '_none_'}`);
    if (r.rea.sourceVersion) L.push(`- Source version: ${md(r.rea.sourceVersion)}`);
    for (const rec of arr(r.rea.records)) {
      L.push(`- ${md(rec.jsonPointer || '/')} ${md(rec.shape)}${rec.operation ? ` ${md(rec.operation)}` : ''}${rec.evidenceId ? ` ${md(rec.evidenceId)}` : ''}${rec.error ? ` error ${md(rec.error.code)}: ${md(rec.error.message)}` : ''}`);
      for (const l of arr(rec.limitations)) L.push(`  - REA limitation: ${md(l)}`);
      for (const u of arr(rec.unknowns)) L.push(`  - REA unknown: ${md(u)}`);
    }
    L.push('');
  }

  const cov = r.coverage ?? { examined: [], excluded: [] };
  L.push('## Coverage', '', `- Examined: ${arr(cov.examined).length}`, `- Excluded: ${arr(cov.excluded).length}`);
  for (const x of arr(cov.excluded)) L.push(`  - ${md(x.path)}: ${md(x.reason)}`);
  L.push('', '## Limitations', '');
  if (arr(r.limitations).length === 0) L.push('_None recorded._');
  for (const l of arr(r.limitations)) L.push(`- ${md(l)}`);
  L.push('', '## Unknowns', '');
  if (arr(r.unknowns).length === 0) L.push('_None recorded._');
  for (const u of arr(r.unknowns)) L.push(`- ${md(u)}`);
  L.push('', '## Attribution basis', '');
  if (arr(att.basis).length === 0) L.push('_No BLA-associated markers or mechanisms observed in scope._');
  for (const x of arr(att.basis)) L.push(`- ${md(x)}`);
  L.push('', `_Classes: ${[...byClass].map(([k, v]) => `${md(k)}=${v}`).join(', ') || 'none'}. All text above was escaped for Markdown; target- and REA-derived quotes are untrusted data (credential shapes are redacted where Anti-BLA produced the quote)._`, '');
  return L.join('\n');
}

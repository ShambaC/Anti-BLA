// Turns recognized REA conditions into conditional, schema-checked next steps.
// Anti-BLA never calls REA; every rea-tool action requires the host to verify the live tools/list schema.
import { makeFinding } from '../core/findings.js';
import type { EvidenceRef, Finding, ReaRecordSummary, SuggestedAction } from '../core/types.js';
import { CATALOG_UPSTREAM, PATTERNS, type CatalogPattern } from './failure-catalog.js';

const SCHEMA_CHECK = 'Verify the connected REA tools/list advertises this operation and the hinted fields; parametersHint is advisory only.';

export function matchPatterns(r: ReaRecordSummary): CatalogPattern[] {
  const text = [r.error?.message, r.error?.remediation, ...r.unknowns, ...r.limitations].filter(Boolean).join('\n');
  return PATTERNS.filter((p) => {
    const m = p.match;
    // Structured diagnostics first.
    const structured: boolean[] = [];
    if (m.code !== undefined) structured.push(r.error?.code === m.code);
    if (m.operation !== undefined) structured.push(r.operation === m.operation);
    if (m.detailsLimitSetting !== undefined) structured.push(r.error?.limit?.setting === m.detailsLimitSetting);
    if (m.detailsResource !== undefined) structured.push(r.error?.resource === m.detailsResource);
    if (m.hasPartialObservation) structured.push(r.error?.partialObservation !== undefined);
    if (m.resourceLimitValues) structured.push(r.resourceLimits.some((x) => m.resourceLimitValues!.includes(x)));
    if (structured.length > 0 && structured.every(Boolean)) return true;
    // Exact catalog substrings second (never fuzzy).
    return p.alsoMatchText.some((t) => text.includes(t));
  });
}

function reaRef(r: ReaRecordSummary, note?: string): EvidenceRef {
  const ref: EvidenceRef = { kind: 'rea', jsonPointer: r.jsonPointer || '/', logicalPath: r.inputPath };
  if (r.evidenceId) ref.reaEvidenceId = r.evidenceId;
  if (note) ref.note = note;
  return ref;
}

const docs = (p: CatalogPattern | undefined) => p?.documentation ?? [];

export function recommend(records: ReaRecordSummary[]): { findings: Finding[]; actions: SuggestedAction[]; matched: Map<number, string[]> } {
  const findings: Finding[] = [];
  const actions: SuggestedAction[] = [];
  const matched = new Map<number, string[]>();
  const failureKeys = new Map<string, number>();

  records.forEach((r, i) => {
    const pats = matchPatterns(r);
    matched.set(i, pats.map((p) => p.id));
    const ids = [r.evidenceId, r.parentEvidenceId, r.error?.partialObservation, r.error?.evidenceReference].filter((x): x is string => !!x);
    const pat = (id: string) => pats.find((p) => p.id === id);

    if (r.shape === 'error') {
      const e = r.error!;
      const key = JSON.stringify([e.code, e.message, e.limit?.value ?? null, r.operation ?? null]);
      failureKeys.set(key, (failureKeys.get(key) ?? 0) + 1);
      findings.push(makeFinding({
        rule: 'rea-reported-error',
        classification: e.code === 'resource_constraint' || pats.some((p) => p.category === 'resource-limit') ? 'resource-limit' : 'analysis-limitation',
        title: `REA error ${e.code}${pats.length ? ` (${pats.map((p) => p.id).join(', ')})` : ''}`,
        observation: `REA returned ${e.code}${e.category ? `/${e.category}` : ''}: ${e.message}`,
        interpretation: 'This is REA\'s observed condition. A capacity error can come from adversarial inflation or a legitimately large input; it is not evidence of BLA by itself. Run anti-bla triage on the same artifact for artifact-side evidence.',
        confidence: 'high',
        evidence: [reaRef(r, 'REA error projection')],
        limitations: pats.length ? [] : ['No catalog pattern matched; Anti-BLA does not invent a recovery for it.'],
      }));
    } else if (r.shape === 'evidence' && r.resourceLimits.length) {
      findings.push(makeFinding({
        rule: 'rea-semantic-resource-limit',
        classification: 'resource-limit',
        title: `REA semantic budget reached: ${r.resourceLimits.join(', ')}`,
        observation: `Evidence ${r.evidenceId} (${r.operation}) records resourceLimit value(s) ${r.resourceLimits.join(', ')}; ${r.unknowns.length} unknown entr(ies) summarized.`,
        interpretation: 'REA preserved completed static facts and marked specific values unknown. The analysis is partial for those scopes, not failed, and not proof of BLA.',
        confidence: 'high',
        evidence: [reaRef(r)],
      }));
    }

    // asar.max_header_bytes / any agent-editable setting carried in details.limit
    const lim = r.error?.limit;
    if (lim && typeof lim.setting === 'string') {
      const required = typeof lim.required_value === 'number' ? lim.required_value : undefined;
      const max = typeof lim.maximum === 'number' ? lim.maximum : undefined;
      const editable = lim.agent_editable === true;
      const invocation = lim.scope === 'rea-invocation';
      if (!editable) {
        actions.push({ kind: 'stop', title: `REA limit ${lim.setting} is not agent-editable`, rationale: 'details.limit.agent_editable is not true.', prerequisites: [], risk: 'read-only', relatedEvidenceIds: ids, exitCriterion: 'Report the limitation; do not patch REA.' });
      } else if (required !== undefined && max !== undefined && required > max) {
        actions.push({ kind: 'stop', title: `Required ${lim.setting}=${required} exceeds REA maximum ${max}`, rationale: 'No supported setting admits this input.', prerequisites: [], risk: 'read-only', relatedEvidenceIds: ids, documentation: docs(pat('asar-header-admission')), exitCriterion: 'Report the scope as unavailable to REA; use Anti-BLA bounded inspection as partial evidence.' });
      } else if (invocation) {
        actions.push({
          kind: 'manual-review',
          title: `Set ${typeof lim.environment === 'string' ? lim.environment : lim.setting} for the next REA CLI invocation`,
          rationale: 'REA CLI failures report scope "rea-invocation": the value applies to the next invocation via its environment seed or per-call parameter.',
          parametersHint: { environment: lim.environment ?? null, parameter: lim.parameter ?? null, value: required ?? `<= ${max ?? 'documented maximum'}` },
          prerequisites: ['Resource policy and host memory allow the value.', 'Run the same command once; do not loop.'],
          risk: 'changes-settings',
          relatedEvidenceIds: ids,
          documentation: docs(pat('asar-header-admission')),
          exitCriterion: 'Stop if the same failure repeats.',
        });
      } else {
        actions.push({
          kind: 'rea-tool',
          title: `Raise ${lim.setting}${required !== undefined ? ` to ${required}` : ''} and retry the same request once`,
          rationale: `REA reported an editable limit (value ${String(lim.value)}, maximum ${String(lim.maximum)}, applies ${String(lim.applies_at ?? 'next_operation')}).`,
          operation: 'update_analysis_settings',
          parametersHint: { changes: [{ setting: lim.setting, action: 'set', value: required ?? `<integer <= ${String(max)}>` }] },
          prerequisites: [SCHEMA_CHECK, 'User/resource policy allows the memory this implies.', 'Wait for active work and cleanup to settle before retrying.'],
          risk: 'changes-settings',
          relatedEvidenceIds: ids,
          documentation: docs(pat('asar-header-admission')).length ? docs(pat('asar-header-admission')) : [`https://github.com/morluto/rea/blob/${CATALOG_UPSTREAM.commit}/docs/design/limits-and-recovery.md`],
          expectedBenefit: 'The unchanged request is admitted (hypothesis; other limits may still apply).',
          exitCriterion: 'Stop if the same error repeats or the setting is not advertised.',
        });
      }
    } else if (pat('asar-header-admission')) {
      actions.push({ kind: 'manual-review', title: 'ASAR admission text without structured details.limit', rationale: 'Only the message matched; read the setting and bounds from REA\'s own error before changing anything.', prerequisites: ['Call inspect_analysis_settings if advertised, or read the error details.'], risk: 'read-only', relatedEvidenceIds: ids, documentation: docs(pat('asar-header-admission')) });
    }

    const view = r.error?.partialObservation ?? (r.error?.resource === 'transport' ? r.error?.evidenceReference : undefined);
    if (view) {
      actions.push({
        kind: 'rea-tool',
        title: 'Inspect the retained partial/complete Evidence instead of rerunning the producer',
        rationale: r.error?.partialObservation ? 'REA retained partial observations for this failure.' : 'The response was too large to deliver; the complete Evidence is retained.',
        operation: 'inspect_analysis_view',
        parametersHint: { source: { kind: 'retained-evidence', evidence_id: view } },
        prerequisites: [SCHEMA_CHECK, 'Same MCP connection (retained references are per connection), or import the exported bundle.'],
        risk: 'read-only',
        relatedEvidenceIds: [view],
        documentation: docs(pat('partial-observation') ?? pat('transport-oversized')),
        expectedBenefit: 'Summary or selected page of already-computed facts.',
        exitCriterion: 'If the reference is missing, use the exported bundle; never invent an ID.',
      });
    }
    if (r.shape === 'evidence' && r.resourceLimits.length && r.evidenceId) {
      const src = r.parentEvidenceId ?? r.evidenceId;
      actions.push({
        kind: 'rea-tool',
        title: 'Read retained module facts and unknown scopes for the budget-limited values',
        rationale: 'Resource-limited analyses keep completed static facts; inspect them before any retry.',
        operation: 'inspect_analysis_view',
        parametersHint: { source: { kind: 'retained-evidence', evidence_id: src } },
        prerequisites: [SCHEMA_CHECK, 'Choose a view kind/collection the connected schema advertises (e.g. a modules page).'],
        risk: 'read-only',
        relatedEvidenceIds: [src],
        documentation: docs(pat('js-semantic-resource-limit')),
        expectedBenefit: 'Facts outside the limited expressions remain usable.',
        exitCriterion: 'If the question depends on the unknown value itself, report it as unknown; do not ratchet global limits.',
      });
      actions.push({ kind: 'cli-command', title: 'Locate the budget-inflating constructs with Anti-BLA', rationale: 'Byte/AST provenance for candidate explosions, getter rings and alias tables.', parametersHint: { command: 'anti-bla triage <selected source file or app dir> --json' }, prerequisites: ['Use the same authorized artifact REA analyzed.'], risk: 'read-only', relatedEvidenceIds: [src] });
    }
    if (pat('sqlite-column-evaluation')) {
      actions.push({ kind: 'rea-tool', title: 'Read SQLite declarations without evaluating generated columns', rationale: 'REA\'s own remediation: omit table and use schema_scope "database", or select readable columns.', operation: 'inspect_sqlite_database', parametersHint: { schema_scope: 'database' }, prerequisites: [SCHEMA_CHECK], risk: 'read-only', relatedEvidenceIds: ids, documentation: docs(pat('sqlite-column-evaluation')), exitCriterion: 'Computed values need the application\'s functions; report them unknown.' });
    }
    if (pat('wasm-interface-capacity')) {
      actions.push({ kind: 'cli-command', title: 'Get a bounded WASM section/import/export inventory', rationale: 'REA 6.8.0 has no documented setting for the WASM interface representation budget; repeating fails the same way.', parametersHint: { command: 'anti-bla inspect <module.wasm> --json' }, prerequisites: [], risk: 'read-only', relatedEvidenceIds: ids, documentation: docs(pat('wasm-interface-capacity')), exitCriterion: 'Signatures/bodies beyond the budget remain unknown.' });
    }
    if (pat('electron-fuse-sentinels')) {
      actions.push({ kind: 'stop', title: 'Electron fuse slice has more sentinels than REA reads', rationale: 'Fixed reader limit in REA 6.8.0; no setting documented.', prerequisites: [], risk: 'read-only', relatedEvidenceIds: ids, exitCriterion: 'Report fuse state as unknown; anti-bla triage lists sentinel offsets.' });
    }
    if (pat('provider-timeout')) {
      actions.push({ kind: 'manual-review', title: 'Follow REA provider_timeout remediation; reuse partial Evidence', rationale: 'Server/provider deadline; REA names the setting and bounds when editable.', prerequisites: ['Read remediation.action and details verbatim.'], risk: 'read-only', relatedEvidenceIds: ids, documentation: docs(pat('provider-timeout')), exitCriterion: 'Do not repeat the unchanged call.' });
    }
    if (pat('client-deadline')) {
      actions.push({ kind: 'manual-review', title: 'Host/client tool deadline, not a REA result', rationale: 'Work or cleanup may still be running; raising REA analysis_timeout_ms cannot fix a shorter client deadline.', prerequisites: ['Increase the host tool deadline (e.g. Codex mcp_servers.<server>.tool_timeout_sec) or report the required setting.'], risk: 'requires-approval', relatedEvidenceIds: ids, documentation: docs(pat('client-deadline')), exitCriterion: 'Do not repeat the unchanged analysis.' });
    }
    if (r.shape === 'error' && pats.length === 0) {
      actions.push({ kind: 'manual-review', title: `Unrecognized REA error ${r.error?.code}`, rationale: 'Not in the pinned failure catalog; follow REA\'s own remediation text only.', prerequisites: ['Read remediation.action; check REA connection-and-recovery guidance.'], risk: 'read-only', relatedEvidenceIds: ids });
    }
  });

  for (const [key, n] of failureKeys) {
    if (n < 2) continue;
    const [code, message] = JSON.parse(key) as [string, string];
    actions.unshift({ kind: 'stop', title: `Same REA failure repeated ${n} times`, rationale: `${code}: ${message.slice(0, 160)} — unchanged inputs/settings will fail again.`, prerequisites: [], risk: 'read-only', exitCriterion: 'Change scope or settings per a supported action, or report the limitation.' });
  }
  return { findings, actions, matched };
}

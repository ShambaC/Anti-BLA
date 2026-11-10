// Version-aware, bounded extraction from REA Evidence / error JSON. Never opens paths found inside it.
import type { ReaRecordSummary } from '../core/types.js';
import { preview } from '../core/findings.js';
import { PATTERNS } from './failure-catalog.js';
import { EVIDENCE_ID_RE, LIMIT_KEYS, isObj, looksLikeError, looksLikeEvidence, type Json, type JsonObject } from './evidence-schema.js';

const MAX_NODES = 200_000;
const MAX_DEPTH = 12;
const MAX_STRINGS = 200;
const MAX_STRING = 2000;

const esc = (k: string) => k.replace(/~/g, '~0').replace(/\//g, '~1');
export const WALK_CAP = 'Anti-BLA stopped walking normalized_result at its node/depth cap; some fields were not summarized.';
// REA strings embed target-derived text: flatten, strip controls, redact credentials, bound length.
const clip = (s: string) => preview(s, MAX_STRING);

export interface ParsedRea {
  records: ReaRecordSummary[];
  /** Raw value for each record, kept so recommendations read the original fields. */
  raw: JsonObject[];
  nodeCapHit: boolean;
  unknownShape: boolean;
}

/** Locate Evidence and error objects (incl. MCP wrappers and CLI envelopes) with a bounded BFS. */
export function locateRecords(root: Json, inputPath: string): ParsedRea {
  const out: ParsedRea = { records: [], raw: [], nodeCapHit: false, unknownShape: false };
  const queue: { v: Json; ptr: string; depth: number }[] = [{ v: root, ptr: '', depth: 0 }];
  // Index-pointer queue; children are enqueued only while under the node cap (no allocation past it).
  let head = 0;
  const enqueue = (v: Json, ptr: string, depth: number) => {
    if (depth > MAX_DEPTH || queue.length >= MAX_NODES) { out.nodeCapHit = true; return; }
    queue.push({ v, ptr, depth });
  };
  while (head < queue.length) {
    const { v, ptr, depth } = queue[head++]!;
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length && !out.nodeCapHit; i++) enqueue(v[i]!, `${ptr}/${i}`, depth + 1);
      continue;
    }
    if (!isObj(v)) continue;
    if (looksLikeEvidence(v)) { out.records.push(summarizeEvidence(v, inputPath, ptr)); out.raw.push(v); continue; }
    if (looksLikeError(v)) { out.records.push(summarizeError(v, inputPath, ptr)); out.raw.push(v); continue; }
    // MCP tool result text content may itself be JSON produced by REA.
    if (Array.isArray(v.content)) {
      v.content.forEach((c, i) => {
        if (isObj(c) && c.type === 'text' && typeof c.text === 'string' && /^\s*[[{]/.test(c.text) && c.text.length < 64 * 1024 * 1024) {
          try { enqueue(JSON.parse(c.text) as Json, `${ptr}/content/${i}/text(json)`, depth + 1); } catch { /* plain text */ }
        }
      });
    }
    for (const k of Object.keys(v).sort()) {
      if (k === 'content') continue;
      if (out.nodeCapHit) break;
      enqueue(v[k]!, `${ptr}/${esc(k)}`, depth + 1);
    }
  }
  if (out.records.length === 0) {
    out.unknownShape = true;
    out.records.push({ inputPath, jsonPointer: '', shape: 'unknown', limitations: [], unknowns: ['No REA Evidence record or canonical error projection was recognized; fields were not interpreted.'], coveragePointers: [], resourceLimits: [] });
  }
  return out;
}

function strings(v: Json | undefined): string[] {
  if (typeof v === 'string') return [clip(v)];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string').slice(0, MAX_STRINGS).map(clip);
  return [];
}

function summarizeEvidence(v: JsonObject, inputPath: string, ptr: string): ReaRecordSummary {
  const s: ReaRecordSummary = {
    inputPath,
    jsonPointer: ptr,
    shape: 'evidence',
    evidenceId: String(v.evidence_id),
    operation: String(v.operation),
    limitations: strings(v.limitations),
    unknowns: [],
    coveragePointers: [],
    resourceLimits: [],
  };
  if (!EVIDENCE_ID_RE.test(s.evidenceId!)) s.limitations.unshift(`evidence_id ${JSON.stringify(s.evidenceId!.slice(0, 80))} does not match the ev_<64 hex> format of rea-agents 6.x; not authenticated.`);
  if (isObj(v.provider)) s.provider = { id: String(v.provider.id ?? ''), name: String(v.provider.name ?? ''), version: typeof v.provider.version === 'string' ? v.provider.version : null };
  if (isObj(v.subject) && isObj(v.subject.digest) && typeof v.subject.digest.sha256 === 'string') s.subjectSha256 = v.subject.digest.sha256;
  if (typeof v.confidence === 'string') s.confidence = v.confidence;
  if (typeof v.authority === 'string') s.authority = v.authority;
  if (v.relationship_coverage !== null && v.relationship_coverage !== undefined) s.coveragePointers.push(`${ptr}/relationship_coverage`);
  walkResult(v.normalized_result ?? null, `${ptr}/normalized_result`, s);
  // REA summaries carry JS budget hits as exact reason strings; map them to their resourceLimit names.
  const js = PATTERNS.find((p) => p.id === 'js-semantic-resource-limit');
  const text = [...s.limitations, ...s.unknowns].join(' | ');
  js?.alsoMatchText.forEach((t, i) => { const name = js.match.resourceLimitValues?.[i]; if (name && text.includes(t)) s.resourceLimits.push(name); });
  s.resourceLimits = [...new Set(s.resourceLimits)].sort();
  return s;
}

/** Collect unknowns/coverage/limits by key name only; values stay attached to their JSON pointer. */
function walkResult(root: Json, base: string, s: ReaRecordSummary): void {
  const st: { v: Json; ptr: string; depth: number }[] = [{ v: root, ptr: base, depth: 0 }];
  let nodes = 0;
  while (st.length) {
    const { v, ptr, depth } = st.pop()!;
    if (++nodes > MAX_NODES) { s.limitations.push(WALK_CAP); return; }
    if (depth > MAX_DEPTH) { if (!s.limitations.includes(WALK_CAP)) s.limitations.push(WALK_CAP); continue; }
    if (Array.isArray(v)) { for (let i = Math.min(v.length, MAX_NODES) - 1; i >= 0; i--) st.push({ v: v[i]!, ptr: `${ptr}/${i}`, depth: depth + 1 }); continue; }
    if (!isObj(v)) continue;
    if (depth === 0 && typeof v.parent_evidence_id === 'string') s.parentEvidenceId = v.parent_evidence_id;
    if (typeof v.resourceLimit === 'string') s.resourceLimits.push(v.resourceLimit);
    if (typeof v.resource_limit === 'string') s.resourceLimits.push(v.resource_limit);
    if (v.status === 'unknown' && typeof v.reason === 'string' && s.unknowns.length < MAX_STRINGS) s.unknowns.push(`${ptr}: ${clip(v.reason)}`);
    for (const k of Object.keys(v).sort().reverse()) {
      const child = v[k]!;
      const cp = `${ptr}/${esc(k)}`;
      if (/^(coverage|source_coverage|completeness|source_selection|source_complete)$/.test(k)) s.coveragePointers.push(cp);
      if (/^(unknowns|source_unknowns|residual_unknowns|unknown_scopes)$/.test(k)) {
        const n = Array.isArray(child) ? child.length : 1;
        if (n > 0 && s.unknowns.length < MAX_STRINGS) s.unknowns.push(`${cp}: ${n} unknown entr${n === 1 ? 'y' : 'ies'}`);
      }
      if (k === 'limitations' && depth > 0) for (const l of strings(child)) if (s.limitations.length < MAX_STRINGS) s.limitations.push(l);
      st.push({ v: child, ptr: cp, depth: depth + 1 });
    }
  }
}

function summarizeError(v: JsonObject, inputPath: string, ptr: string): ReaRecordSummary {
  const details = isObj(v.details) ? v.details : {};
  const err: NonNullable<ReaRecordSummary['error']> = { code: String(v.code), message: clip(String(v.message)) };
  if (typeof v.category === 'string') err.category = v.category;
  if (typeof v.retryable === 'boolean') err.retryable = v.retryable;
  if (isObj(v.remediation) && typeof v.remediation.action === 'string') err.remediation = clip(v.remediation.action);
  if (isObj(details.limit)) {
    const lim: Record<string, unknown> = {};
    for (const k of LIMIT_KEYS) { const x = details.limit[k]; if (x === null || ['string', 'number', 'boolean'].includes(typeof x)) if (x !== undefined) lim[k] = x; }
    err.limit = lim;
  }
  const po = details.partial_observation;
  if (typeof po === 'string') err.partialObservation = po;
  else if (isObj(po) && typeof po.evidence_id === 'string') err.partialObservation = po.evidence_id;
  if (isObj(details.reported_limits)) {
    const ref = details.reported_limits.evidence_reference;
    if (typeof ref === 'string') err.evidenceReference = ref;
    else if (isObj(ref) && typeof ref.evidence_id === 'string') err.evidenceReference = ref.evidence_id;
  }
  if (typeof details.resource === 'string') err.resource = details.resource;
  const s: ReaRecordSummary = { inputPath, jsonPointer: ptr, shape: 'error', limitations: [], unknowns: [], coveragePointers: [], resourceLimits: [], error: err };
  if (typeof details.operation === 'string') s.operation = details.operation;
  return s;
}

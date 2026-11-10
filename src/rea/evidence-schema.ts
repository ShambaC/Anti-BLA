// Shapes observed in rea-agents 6.8.0 (src/domain/evidence.ts, src/contracts/errorSchemas.ts).
// Recognition is deliberately structural and conservative: unknown shapes are reported, not reinterpreted.

export const EVIDENCE_ID_RE = /^ev_[0-9a-f]{64}$/;

/** Top-level Evidence fields in rea-agents 6.8.0 evidenceBaseSchema. */
export const EVIDENCE_FIELDS = [
  'evidence_id', 'subject', 'provider', 'analysis_profile', 'predicate_type', 'operation', 'parameters',
  'caller_input_path', 'caller_input_paths', 'raw_result', 'normalized_result', 'confidence', 'authority',
  'environment', 'limitations', 'relationship_coverage', 'locations', 'evidence_links',
] as const;

/** `code` values of the canonical analysis error projection (errorSchemas.ts). */
export const ERROR_CODES = new Set([
  'invalid_request', 'access_denied', 'artifact_changed', 'unreadable_output', 'capability_unavailable',
  'unsupported_target', 'provider_unavailable', 'provider_timeout', 'resource_constraint', 'cancelled',
  'artifact_integrity_mismatch', 'artifact_operation_failed', 'evidence_integrity_mismatch', 'truncated',
  'process_capture_failed', 'cleanup_incomplete', 'revision_conflict', 'configuration_invalid',
  'target_unavailable', 'execution_failure',
]);

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

export const isObj = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);

export function looksLikeEvidence(v: JsonObject): boolean {
  return typeof v.evidence_id === 'string' && typeof v.operation === 'string' && 'normalized_result' in v;
}

export function looksLikeError(v: JsonObject): boolean {
  return typeof v.code === 'string' && ERROR_CODES.has(v.code) && typeof v.message === 'string';
}

/** Detail keys copied from details.limit (limits-and-recovery.md); primitives only. */
export const LIMIT_KEYS = ['setting', 'value', 'effective_value', 'minimum', 'maximum', 'unit', 'required_value', 'source', 'agent_editable', 'scope', 'applies_at', 'rea_restart_required', 'parameter', 'environment'];

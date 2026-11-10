import type { AnalysisStatus, AttributionStatus, Finding } from './types.js';

const RANK: Record<AnalysisStatus, number> = { complete: 0, partial: 1, unsupported: 2, failed: 3 };

/** Overall status: complete only when every artifact is complete and nothing was skipped. */
export function aggregateStatus(statuses: AnalysisStatus[], skippedSomething: boolean): AnalysisStatus {
  if (statuses.length === 0) return skippedSomething ? 'failed' : 'unsupported';
  if (statuses.every((s) => s === 'failed')) return 'failed';
  if (statuses.every((s) => s === 'unsupported')) return 'unsupported';
  const worst = Math.max(...statuses.map((s) => RANK[s]));
  if (worst === 0 && !skippedSomething) return 'complete';
  return 'partial';
}

/**
 * Structural mechanisms that mirror documented BLA families (see docs/limitation-matrix.md).
 * One medium/high instance is enough for "bla-like-mechanisms".
 */
const STRUCTURAL_RULES = new Set([
  'js-literal-alternative-explosion',
  'js-primitive-byte-charge',
  'js-getter-ring',
  'js-alias-table',
  'js-alias-chain',
  'js-dynamic-receiver-getters',
  'wasm-export-inflation',
  'sqlite-generated-column-unknown-function',
  'sourcemap-unreferenced-content',
  'electron-fuse-sentinel-flood',
  'agent-directed-instruction',
]);
/** Pure capacity observations (large but possibly legitimate inputs): need two before they count. */
const CAPACITY_RULES = new Set(['asar-header-exceeds-rea-default', 'wasm-interface-representation', 'js-expression-depth', 'sourcemap-bundle-mismatch']);

/**
 * Attribution never reaches "confirmed". Markers can be planted and mechanisms
 * occur in legitimate software; both are reported as hypotheses with their basis.
 */
export function attribution(findings: Finding[]): { status: AttributionStatus; basis: string[] } {
  const markers = findings.filter((f) => f.rule === 'bla-marker-string');
  const strong = (f: Finding) => f.confidence !== 'low';
  const structural = findings.filter((f) => STRUCTURAL_RULES.has(f.rule) && strong(f));
  const capacity = findings.filter((f) => CAPACITY_RULES.has(f.rule) && strong(f));
  const mech = structural.length > 0 || capacity.length >= 2 ? [...structural, ...capacity] : [];
  const basis = [...markers, ...mech].map((f) => `${f.id} ${f.rule}`).sort();
  if (markers.length) return { status: 'bla-markers-observed', basis };
  if (mech.length) return { status: 'bla-like-mechanisms', basis };
  return { status: 'none-observed', basis: [] };
}

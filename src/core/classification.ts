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

/** Mechanism-level rules that correspond to documented BLA families (see docs/limitation-matrix.md). */
const MECHANISM_RULES = new Set([
  'js-literal-alternative-explosion',
  'js-primitive-byte-charge',
  'js-expression-depth',
  'js-getter-ring',
  'js-alias-table',
  'asar-header-exceeds-rea-default',
  'wasm-interface-representation',
  'wasm-export-inflation',
  'sqlite-generated-column-unknown-function',
  'sourcemap-unreferenced-content',
  'sourcemap-bundle-mismatch',
  'electron-fuse-sentinel-flood',
  'agent-directed-instruction',
]);

/**
 * Attribution never reaches "confirmed". Markers can be planted and mechanisms
 * occur in legitimate software; both are reported as hypotheses with their basis.
 */
export function attribution(findings: Finding[]): { status: AttributionStatus; basis: string[] } {
  const markers = findings.filter((f) => f.rule === 'bla-marker-string');
  const mech = findings.filter((f) => MECHANISM_RULES.has(f.rule) && f.confidence !== 'low');
  const basis = [...markers, ...mech].map((f) => `${f.id} ${f.rule}`).sort();
  if (markers.length) return { status: 'bla-markers-observed', basis };
  if (mech.length) return { status: 'bla-like-mechanisms', basis };
  return { status: 'none-observed', basis: [] };
}

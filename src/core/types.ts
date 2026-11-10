// Versioned report contract. See docs/tool-contracts.md for field semantics.

export const REPORT_SCHEMA_VERSION = 'anti-bla-report/v1' as const;

export type AnalysisStatus = 'complete' | 'partial' | 'failed' | 'unsupported';
export type Confidence = 'low' | 'medium' | 'high';
export type EvidenceKind = 'bytes' | 'ast' | 'format' | 'rea' | 'derived';
export type FindingClass =
  | 'possible-poisoning'
  | 'possible-decoy'
  | 'resource-limit'
  | 'metadata-only'
  | 'reachability-unknown'
  | 'integrity-dependency'
  | 'runtime-discrepancy'
  | 'analysis-limitation';

export interface ArtifactIdentity {
  path: string;
  logicalPath: string;
  sha256: string;
  sizeBytes: number;
  detectedFormat: string;
  formatConfidence: Confidence;
  analysisStatus: AnalysisStatus;
  /** Analyzer-specific measured facts (e.g. ASAR headerBytes, WASM export counts). Bounded; untrusted names are previewed. */
  facts?: Record<string, unknown>;
}

export interface EvidenceRef {
  kind: EvidenceKind;
  artifactSha256?: string;
  logicalPath?: string;
  byteStart?: number;
  byteEnd?: number;
  astLocation?: { line: number; column: number };
  reaEvidenceId?: string;
  jsonPointer?: string;
  note?: string;
}

export interface Finding {
  id: string;
  rule: string;
  classification: FindingClass;
  title: string;
  observation: string;
  interpretation: string;
  confidence: Confidence;
  evidence: EvidenceRef[];
  limitations: string[];
  nextSteps: string[];
  metrics?: Record<string, number | string | boolean>;
}

export interface SuggestedAction {
  kind: 'rea-tool' | 'cli-command' | 'manual-review' | 'stop';
  title: string;
  rationale: string;
  operation?: string;
  parametersHint?: Record<string, unknown>;
  prerequisites: string[];
  risk: 'read-only' | 'changes-settings' | 'requires-approval';
  relatedEvidenceIds?: string[];
  documentation?: string[];
  expectedBenefit?: string;
  exitCriterion?: string;
}

/** Attribution is never "confirmed": static evidence cannot prove which tool produced an artifact. */
export type AttributionStatus = 'none-observed' | 'bla-like-mechanisms' | 'bla-markers-observed';

export interface AntiBlaReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  command: 'triage' | 'inspect' | 'rea-evidence';
  analysisStatus: AnalysisStatus;
  analyzedAt: string;
  toolVersion: string;
  artifacts: ArtifactIdentity[];
  findings: Finding[];
  suggestedActions: SuggestedAction[];
  coverage: { examined: string[]; excluded: { path: string; reason: string }[] };
  limitations: string[];
  unknowns: string[];
  attribution: { status: AttributionStatus; basis: string[] };
  rea?: ReaSummary;
  budgets: {
    elapsedMs: number;
    bytesRead: number;
    bytesHashed: number;
    truncated: boolean;
    limits: Record<string, number>;
  };
}

export interface ReaSummary {
  evidenceIds: string[];
  sourceVersion?: string;
  records: ReaRecordSummary[];
}

export interface ReaRecordSummary {
  inputPath: string;
  jsonPointer: string;
  shape: 'evidence' | 'error' | 'unknown';
  evidenceId?: string;
  parentEvidenceId?: string;
  operation?: string;
  provider?: { id: string; name: string; version: string | null };
  subjectSha256?: string;
  confidence?: string;
  authority?: string;
  limitations: string[];
  unknowns: string[];
  coveragePointers: string[];
  resourceLimits: string[];
  error?: {
    code?: string;
    category?: string;
    message?: string;
    retryable?: boolean;
    remediation?: string;
    limit?: Record<string, unknown>;
    partialObservation?: string;
    evidenceReference?: string;
    resource?: string;
  };
}

/** Input handed to every format analyzer. `bytes` is the budget-bounded prefix already read. */
export interface AnalyzeContext {
  path: string;
  logicalPath: string;
  sha256: string;
  sizeBytes: number;
  bytes: Buffer;
  truncated: boolean;
  budget: import('./budgets.js').Budget;
  /** Returns the absolute path of a file inside the same user-selected scan, if present. */
  sibling?: (logicalPath: string) => string | undefined;
  /** ASAR member to select (inspect --member). */
  member?: string;
}

/** Result of one format analyzer over one artifact. */
export interface AnalyzerResult {
  status: AnalysisStatus;
  format: string;
  formatConfidence: Confidence;
  findings: Finding[];
  limitations: string[];
  unknowns: string[];
  facts: Record<string, unknown>;
  suggestedActions?: SuggestedAction[];
}

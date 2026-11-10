import { createHash } from 'node:crypto';
import type { Confidence, EvidenceRef, Finding, FindingClass } from './types.js';

export interface FindingInput {
  rule: string;
  classification: FindingClass;
  title: string;
  observation: string;
  interpretation: string;
  confidence: Confidence;
  evidence: EvidenceRef[];
  limitations?: string[];
  nextSteps?: string[];
  metrics?: Record<string, number | string | boolean>;
}

/** Stable id from rule + first evidence anchor; independent of time and iteration order. */
export function makeFinding(f: FindingInput): Finding {
  if (f.evidence.length === 0) throw new Error(`Finding ${f.rule} has no evidence`);
  const anchor = JSON.stringify([f.rule, f.title, f.evidence.map((e) => [e.artifactSha256, e.logicalPath, e.byteStart, e.byteEnd, e.astLocation?.line, e.astLocation?.column, e.reaEvidenceId, e.jsonPointer])]);
  const id = 'F-' + createHash('sha256').update(anchor).digest('hex').slice(0, 12);
  const out: Finding = {
    id,
    rule: f.rule,
    classification: f.classification,
    title: f.title,
    observation: f.observation,
    interpretation: f.interpretation,
    confidence: f.confidence,
    evidence: f.evidence,
    limitations: f.limitations ?? [],
    nextSteps: f.nextSteps ?? [],
  };
  if (f.metrics) out.metrics = f.metrics;
  return out;
}

const CREDENTIAL_SHAPES: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g,
  /gh[pousr]_[A-Za-z0-9]{20,}/g,
  /sk-[A-Za-z0-9_-]{16,}/g,
  /xox[abprs]-[A-Za-z0-9-]{10,}/g,
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
];

/** Redact credential-shaped substrings so reports never echo apparent secrets verbatim. */
export function redact(text: string): string {
  let s = text;
  for (const re of CREDENTIAL_SHAPES) {
    s = s.replace(re, (m: string, bearer?: string) => {
      const keep = typeof bearer === 'string' && m.startsWith(bearer) ? bearer : m.slice(0, 4);
      return `${keep}[REDACTED:${m.length - keep.length}ch]`;
    });
  }
  return s;
}

/** Bounded, single-line, control-free, redacted preview of untrusted text. */
export function preview(text: string, maxChars: number): string {
  const flat = text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim();
  const red = redact(flat);
  return red.length > maxChars ? red.slice(0, maxChars) + `…(+${red.length - maxChars}ch)` : red;
}

export function capFindings(findings: Finding[], max: number): { kept: Finding[]; dropped: number } {
  if (findings.length <= max) return { kept: findings, dropped: 0 };
  // Keep the most decision-relevant first: confidence, then deterministic id.
  const rank: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };
  const sorted = [...findings].sort((a, b) => rank[a.confidence] - rank[b.confidence] || (a.id < b.id ? -1 : 1));
  return { kept: sorted.slice(0, max), dropped: findings.length - max };
}

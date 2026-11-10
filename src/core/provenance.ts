import type { EvidenceRef } from './types.js';

/** Maps UTF-16 indices of a decoded text back to UTF-8 byte offsets and 1-based line/column. */
export class TextIndex {
  private readonly lineStarts: number[] = [0];
  constructor(readonly text: string) {
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
  }
  lineCol(index: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: index - this.lineStarts[lo]! + 1 };
  }
  private lastIndex = 0;
  private lastByte = 0;
  byteOffset(index: number): number {
    // Resume from the previous answer when callers move forward (the common case).
    if (index < this.lastIndex) { this.lastIndex = 0; this.lastByte = 0; }
    this.lastByte += Buffer.byteLength(this.text.slice(this.lastIndex, index), 'utf8');
    this.lastIndex = index;
    return this.lastByte;
  }
}

export function textRef(sha: string, logicalPath: string, idx: TextIndex, start: number, end: number, note?: string): EvidenceRef {
  const byteStart = idx.byteOffset(start);
  const ref: EvidenceRef = {
    kind: 'ast',
    artifactSha256: sha,
    logicalPath,
    byteStart,
    byteEnd: byteStart + Buffer.byteLength(idx.text.slice(start, end), 'utf8'),
    astLocation: idx.lineCol(start),
  };
  if (note) ref.note = note;
  return ref;
}

export function byteRef(sha: string, logicalPath: string, byteStart: number, byteEnd: number, note?: string, kind: 'bytes' | 'format' = 'bytes'): EvidenceRef {
  const ref: EvidenceRef = { kind, artifactSha256: sha, logicalPath, byteStart, byteEnd };
  if (note) ref.note = note;
  return ref;
}

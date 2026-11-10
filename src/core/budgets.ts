// Single budget context shared by every detector. All caps are hard limits.

export interface BudgetLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxTimeMs: number;
  maxDepth: number;
  maxFindings: number;
  maxAstNodes: number;
  jsParseTimeoutMs: number;
  jsWorkerHeapMb: number;
  maxHeaderBytes: number;
  maxScanBytes: number;
  maxListEntries: number;
  maxPreviewChars: number;
}

export const DEFAULT_LIMITS: Readonly<BudgetLimits> = Object.freeze({
  maxFiles: 2000,
  maxFileBytes: 32 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
  maxTimeMs: 30_000,
  maxDepth: 32,
  maxFindings: 500,
  maxAstNodes: 2_000_000,
  jsParseTimeoutMs: 10_000,
  jsWorkerHeapMb: 512,
  // Our own ASAR header parse cap; independent of REA's admission setting.
  maxHeaderBytes: 64 * 1024 * 1024,
  // Text scanning window for generic/binary content per file.
  maxScanBytes: 4 * 1024 * 1024,
  maxListEntries: 200,
  maxPreviewChars: 120,
});

export const CLI_LIMIT_FLAGS: Record<string, keyof BudgetLimits> = {
  '--max-files': 'maxFiles',
  '--max-file-bytes': 'maxFileBytes',
  '--max-total-bytes': 'maxTotalBytes',
  '--max-time-ms': 'maxTimeMs',
  '--max-depth': 'maxDepth',
  '--max-findings': 'maxFindings',
};

export class Budget {
  readonly limits: Readonly<BudgetLimits>;
  readonly startedAt: number;
  bytesRead = 0;
  bytesHashed = 0;
  filesSeen = 0;
  truncated = false;
  readonly reasons: string[] = [];

  constructor(limits: Partial<BudgetLimits> = {}, now: () => number = Date.now) {
    const merged = { ...DEFAULT_LIMITS, ...limits };
    for (const [k, v] of Object.entries(merged)) {
      if (!Number.isSafeInteger(v) || v < 1) throw new RangeError(`Budget ${k} must be a positive safe integer`);
    }
    this.limits = Object.freeze(merged);
    this.now = now;
    this.startedAt = now();
  }
  private readonly now: () => number;

  elapsedMs(): number {
    return this.now() - this.startedAt;
  }
  remainingMs(): number {
    return Math.max(0, this.limits.maxTimeMs - this.elapsedMs());
  }
  timedOut(): boolean {
    return this.remainingMs() === 0;
  }

  /** How many bytes of a file may be read right now (0 = none). */
  readAllowance(fileSize: number): number {
    const left = this.limits.maxTotalBytes - this.bytesRead;
    return Math.max(0, Math.min(fileSize, this.limits.maxFileBytes, left));
  }
  chargeRead(n: number): void {
    this.bytesRead += n;
  }

  markTruncated(reason: string): void {
    this.truncated = true;
    if (!this.reasons.includes(reason)) this.reasons.push(reason);
  }
}

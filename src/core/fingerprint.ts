import { readBounded, readRange, sameStamp, sha256File, stampOf, type FileStamp } from './files.js';
import type { Budget } from './budgets.js';

export interface Fingerprint {
  sha256: string;
  size: number;
  bytes: Buffer;
  truncated: boolean;
  head: Buffer;
  before: FileStamp;
}

/** Hash (streaming), then read a budgeted prefix. Returns null if the time budget ran out while hashing. */
export async function fingerprint(path: string, budget: Budget): Promise<Fingerprint | null> {
  const before = await stampOf(path);
  const sha256 = await sha256File(path, budget);
  if (sha256 === null) return null;
  const { bytes, truncated } = await readBounded(path, before.size, budget);
  // Format detection always gets a small head, even when the total read budget is spent.
  const head = bytes.length >= 64 || !truncated ? bytes : await readRange(path, 0, 4096);
  return { sha256, size: before.size, bytes, truncated, head, before };
}

export async function changedSince(path: string, before: FileStamp): Promise<boolean> {
  try {
    return !sameStamp(before, await stampOf(path));
  } catch {
    return true;
  }
}

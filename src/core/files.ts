// Read-only file access: every open uses flag 'r'; nothing in this module writes to targets.
import { createHash } from 'node:crypto';
import { open, lstat, readdir, realpath, stat } from 'node:fs/promises';
import { basename, isAbsolute, relative, resolve, sep } from 'node:path';
import type { Budget } from './budgets.js';

export interface FileStamp {
  size: number;
  mtimeMs: number;
  ino: number;
  dev: number;
}

export async function stampOf(path: string): Promise<FileStamp> {
  const s = await stat(path);
  return { size: s.size, mtimeMs: s.mtimeMs, ino: s.ino, dev: s.dev };
}

export function sameStamp(a: FileStamp, b: FileStamp): boolean {
  return a.size === b.size && a.mtimeMs === b.mtimeMs && a.ino === b.ino && a.dev === b.dev;
}

/** Streaming SHA-256 with constant memory. Returns null if the deadline passes first. */
export async function sha256File(path: string, budget?: Budget): Promise<string | null> {
  const fh = await open(path, 'r');
  try {
    const hash = createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let pos = 0;
    for (;;) {
      if (budget?.timedOut()) return null;
      const { bytesRead } = await fh.read(chunk, 0, chunk.length, pos);
      if (bytesRead === 0) break;
      hash.update(chunk.subarray(0, bytesRead));
      pos += bytesRead;
      if (budget) budget.bytesHashed += bytesRead;
    }
    return hash.digest('hex');
  } finally {
    await fh.close();
  }
}

export function sha256Bytes(b: Uint8Array): string {
  return createHash('sha256').update(b).digest('hex');
}

/**
 * Read [start, start+length) clamped to the real file length. Never allocates
 * more than `length` bytes and never trusts a caller-supplied offset past EOF.
 */
export async function readRange(path: string, start: number, length: number): Promise<Buffer> {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0) {
    throw new RangeError(`Invalid read range ${start}+${length}`);
  }
  const fh = await open(path, 'r');
  try {
    const size = (await fh.stat()).size;
    if (start >= size || length === 0) return Buffer.alloc(0);
    const n = Math.min(length, size - start);
    const buf = Buffer.alloc(n);
    let off = 0;
    while (off < n) {
      const { bytesRead } = await fh.read(buf, off, n - off, start + off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    return off === n ? buf : buf.subarray(0, off);
  } finally {
    await fh.close();
  }
}

/** Budget-charged prefix read. Returns the bytes and whether the file was cut short. */
export async function readBounded(path: string, size: number, budget: Budget): Promise<{ bytes: Buffer; truncated: boolean }> {
  const allowed = budget.readAllowance(size);
  const bytes = await readRange(path, 0, allowed);
  budget.chargeRead(bytes.length);
  return { bytes, truncated: bytes.length < size };
}

export function isInside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export interface WalkEntry {
  path: string;
  logicalPath: string;
  size: number;
}
export interface WalkResult {
  files: WalkEntry[];
  excluded: { path: string; reason: string }[];
}

/**
 * Deterministic traversal: names sorted by code unit, symlinks followed only
 * when their real target stays inside the real root, hard links / repeated
 * targets reported once.
 */
export async function walk(rootArg: string, budget: Budget): Promise<WalkResult> {
  const root = await realpath(resolve(rootArg));
  const files: WalkEntry[] = [];
  const excluded: { path: string; reason: string }[] = [];
  const seen = new Set<string>();
  const toLogical = (p: string) => relative(root, p).split(sep).join('/') || '.';

  const rootStat = await stat(root);
  if (rootStat.isFile()) {
    return { files: [{ path: root, logicalPath: basename(root), size: rootStat.size }], excluded };
  }

  // Explicit stack (no recursion): depth-first, entries visited in sorted code-unit order.
  const sorted = (xs: string[]) => xs.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const stack: { p: string; depth: number }[] = [];
  const pushChildren = async (dir: string, depth: number) => {
    let names: string[];
    try {
      names = sorted(await readdir(dir));
    } catch (e) {
      excluded.push({ path: toLogical(dir), reason: `unreadable directory: ${(e as NodeJS.ErrnoException).code ?? 'error'}` });
      return;
    }
    for (let i = names.length - 1; i >= 0; i--) stack.push({ p: resolve(dir, names[i]!), depth });
  };
  await pushChildren(root, 1);
  while (stack.length > 0) {
    const { p, depth } = stack.pop()!;
    const logical = toLogical(p);
    if (budget.timedOut()) {
      excluded.push({ path: logical, reason: 'time budget exhausted before visit' });
      budget.markTruncated('time budget exhausted during traversal');
      continue;
    }
    let st;
    try {
      const ls = await lstat(p);
      st = ls;
      if (ls.isSymbolicLink()) {
        let target: string;
        try {
          target = await realpath(p);
          st = await stat(target);
        } catch {
          excluded.push({ path: logical, reason: 'dangling or looping symlink' });
          continue;
        }
        if (!isInside(root, target)) {
          excluded.push({ path: logical, reason: 'symlink target outside selected root (not followed)' });
          continue;
        }
      }
    } catch (e) {
      excluded.push({ path: logical, reason: `lstat failed: ${(e as NodeJS.ErrnoException).code ?? 'error'}` });
      continue;
    }
    // BigInt inode: NTFS file IDs exceed 2^53 and would collide as plain numbers.
    let ino = 0n;
    let dev = 0n;
    try { const b = await stat(p, { bigint: true }); ino = b.ino; dev = b.dev; } catch { /* keep 0: no dedupe */ }
    const key = `${dev}:${ino}`;
    if (ino !== 0n && seen.has(key)) {
      excluded.push({ path: logical, reason: 'alias of an already-listed file or directory (hard link / symlink)' });
      continue;
    }
    if (ino !== 0n) seen.add(key);
    if (st.isDirectory()) {
      if (depth > budget.limits.maxDepth) {
        excluded.push({ path: logical, reason: `max depth ${budget.limits.maxDepth} reached` });
        budget.markTruncated('max depth reached');
      } else await pushChildren(p, depth + 1);
    } else if (st.isFile()) {
      if (files.length >= budget.limits.maxFiles) {
        excluded.push({ path: logical, reason: `max files ${budget.limits.maxFiles} reached` });
        budget.markTruncated('max files reached');
      } else files.push({ path: p, logicalPath: logical, size: st.size });
    } else {
      excluded.push({ path: logical, reason: 'not a regular file' });
    }
  }
  return { files, excluded };
}

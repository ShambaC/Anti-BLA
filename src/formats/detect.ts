import { extname } from 'node:path';
import type { Confidence } from '../core/types.js';

export interface Detection {
  format: string;
  confidence: Confidence;
  notes: string[];
}

const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx']);
const TS_EXT = new Set(['.ts', '.mts', '.cts', '.tsx']);
const TEXT_EXT = new Set(['.json', '.md', '.txt', '.html', '.htm', '.css', '.yml', '.yaml', '.xml', '.svg', '.toml', '.ini', '.cfg', '.sql']);

function startsWith(b: Uint8Array, sig: number[]): boolean {
  if (b.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[i] !== sig[i]) return false;
  return true;
}

/** Structural ASAR check on the first 17 bytes (Chromium Pickle framing + JSON start). */
export function looksLikeAsar(b: Uint8Array): boolean {
  if (b.length < 17) return false;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return dv.getUint32(0, true) === 4 && dv.getUint32(8, true) >= 4 && dv.getUint32(12, true) > 0 && b[16] === 0x7b;
}

function isMostlyText(b: Uint8Array): boolean {
  const n = Math.min(b.length, 8192);
  if (n === 0) return true;
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i]!;
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) bad++;
  }
  return bad / n < 0.02;
}

/** Magic and structure first; extension only breaks ties for formats without magic. */
export function detectFormat(head: Uint8Array, logicalPath: string): Detection {
  const ext = extname(logicalPath).toLowerCase();
  const notes: string[] = [];
  const byMagic = (format: string, confidence: Confidence = 'high'): Detection => {
    const expected: Record<string, string[]> = { wasm: ['.wasm'], sqlite: ['.sqlite', '.db', '.sqlite3', '.db3'], asar: ['.asar'] };
    if ((JS_EXT.has(ext) || TS_EXT.has(ext)) && format !== 'javascript') notes.push(`extension ${ext} disagrees with ${format} magic bytes; magic wins`);
    else if (expected[format] && ext && !expected[format]!.includes(ext)) notes.push(`extension ${ext} is unusual for ${format}`);
    return { format, confidence, notes };
  };

  if (startsWith(head, [0x00, 0x61, 0x73, 0x6d])) return byMagic('wasm');
  if (startsWith(head, [...Buffer.from('SQLite format 3\0', 'latin1')])) return byMagic('sqlite');
  if (looksLikeAsar(head)) return byMagic('asar', ext === '.asar' ? 'high' : 'medium');
  if (startsWith(head, [0x7f, 0x45, 0x4c, 0x46])) return byMagic('elf');
  if (startsWith(head, [0x4d, 0x5a])) return byMagic('pe', 'medium');
  if (startsWith(head, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(head, [0xce, 0xfa, 0xed, 0xfe]) || startsWith(head, [0xfe, 0xed, 0xfa, 0xcf]) || startsWith(head, [0xfe, 0xed, 0xfa, 0xce])) return byMagic('macho');
  if (startsWith(head, [0xca, 0xfe, 0xba, 0xbe])) return byMagic('macho-fat-or-java-class', 'low');
  if (startsWith(head, [0x50, 0x4b, 0x03, 0x04])) return byMagic('zip');
  if (startsWith(head, [0x1f, 0x8b])) return byMagic('gzip');
  if (startsWith(head, [...Buffer.from('GGUF', 'latin1')])) return byMagic('gguf');
  if (ext === '.safetensors') return { format: 'safetensors', confidence: 'medium', notes };
  if (ext === '.pyc') return { format: 'pyc', confidence: 'medium', notes };

  const text = isMostlyText(head);
  if (ext === '.asar') {
    notes.push('.asar extension but no valid ASAR pickle header');
    return { format: 'asar', confidence: 'low', notes };
  }
  if (!text) {
    if (JS_EXT.has(ext) || TS_EXT.has(ext)) notes.push(`extension ${ext} but content is binary`);
    return { format: 'binary', confidence: 'low', notes };
  }
  if (ext === '.map') return { format: 'source-map', confidence: 'medium', notes };
  if (JS_EXT.has(ext)) return { format: 'javascript', confidence: 'medium', notes };
  if (TS_EXT.has(ext)) return { format: 'typescript', confidence: 'medium', notes };
  if (TEXT_EXT.has(ext)) return { format: ext === '.json' ? 'json' : 'text', confidence: 'medium', notes };
  return { format: 'text', confidence: 'low', notes };
}

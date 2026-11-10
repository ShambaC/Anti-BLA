// JSON.parse keeps the last of duplicate keys silently. Attackers can exploit that ambiguity
// (different parsers pick different values), so we detect it with a bounded, iterative scan.
// Frames keep a parent index, not a full pointer string, so memory stays O(depth).

export interface DuplicateKey {
  pointer: string;
  key: string;
  offset: number;
}

const unesc = (s: string) => {
  try { return JSON.parse(`"${s}"`) as string; } catch { return s; }
};
const escPtr = (k: string) => k.replace(/~/g, '~0').replace(/\//g, '~1');

const MAX_DEPTH = 100_000;

/** Returns up to `cap` duplicate keys with JSON pointers of their parent object. Assumes syntactically valid JSON. */
export function findDuplicateKeys(text: string, cap = 20): DuplicateKey[] {
  const out: DuplicateKey[] = [];
  type Frame = { obj: boolean; keys: Set<string> | null; index: number; pendingKey: string | null };
  const stack: Frame[] = [];
  const pointer = (depth: number) => {
    let p = '';
    for (let d = 0; d < depth; d++) {
      const f = stack[d]!;
      p += '/' + (f.obj ? escPtr(f.pendingKey ?? '') : String(f.index));
    }
    return p || '/';
  };
  let i = 0;
  while (i < text.length && out.length < cap) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      let k = j + 1;
      while (k < text.length && (text[k] === ' ' || text[k] === '\n' || text[k] === '\r' || text[k] === '\t')) k++;
      if (top?.obj && text[k] === ':') {
        const key = unesc(text.slice(i + 1, j));
        if (top.keys!.has(key)) out.push({ pointer: pointer(stack.length - 1), key, offset: i });
        top.keys!.add(key);
        top.pendingKey = key;
      }
      i = j + 1;
      continue;
    }
    if (c === '{' || c === '[') {
      if (stack.length >= MAX_DEPTH) break;
      stack.push({ obj: c === '{', keys: c === '{' ? new Set() : null, index: 0, pendingKey: null });
    } else if (c === '}' || c === ']') {
      stack.pop();
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top && !top.obj) top.index++;
    }
    i++;
  }
  return out;
}

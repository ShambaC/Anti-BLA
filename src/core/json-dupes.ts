// JSON.parse keeps the last of duplicate keys silently. Attackers can exploit that ambiguity
// (different parsers pick different values), so we detect it with a bounded, iterative scan.

export interface DuplicateKey {
  pointer: string;
  key: string;
  offset: number;
}

const unesc = (s: string) => {
  try { return JSON.parse(`"${s}"`) as string; } catch { return s; }
};
const escPtr = (k: string) => k.replace(/~/g, '~0').replace(/\//g, '~1');

/** Returns up to `cap` duplicate keys with JSON pointers of their parent object. Assumes syntactically valid JSON. */
export function findDuplicateKeys(text: string, cap = 20): DuplicateKey[] {
  const out: DuplicateKey[] = [];
  type Frame = { obj: boolean; keys: Set<string> | null; ptr: string; index: number; pendingKey: string | null };
  const stack: Frame[] = [];
  let i = 0;
  const childPtr = (f: Frame) => (f.obj ? `${f.ptr}/${escPtr(f.pendingKey ?? '')}` : `${f.ptr}/${f.index}`);
  while (i < text.length && out.length < cap) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const raw = text.slice(i + 1, j);
      const top = stack[stack.length - 1];
      let k = j + 1;
      while (k < text.length && /\s/.test(text[k]!)) k++;
      if (top?.obj && text[k] === ':') {
        const key = unesc(raw);
        if (top.keys!.has(key)) out.push({ pointer: top.ptr || '/', key, offset: i });
        top.keys!.add(key);
        top.pendingKey = key;
      }
      i = j + 1;
      continue;
    }
    if (c === '{' || c === '[') {
      const top = stack[stack.length - 1];
      const ptr = top ? childPtr(top) : '';
      stack.push({ obj: c === '{', keys: c === '{' ? new Set() : null, ptr, index: 0, pendingKey: null });
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

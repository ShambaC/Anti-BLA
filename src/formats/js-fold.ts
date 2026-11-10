// Bounded, sound constant folding over JS expressions. Never evaluates target code:
// it interprets a tiny pure subset (literals, arithmetic/bitwise/compare/logical ops,
// ?:, Math.imul, single-declaration module-level consts) and returns every possible value.
// A guard or string is "proven" only if every enumerated possibility agrees.
import type tsType from 'typescript';

export type Val = number | boolean | string;
const MAX_VALUES = 16;
const MAX_ASSIGNMENTS = 64;
const MAX_DEPTH = 64;

export class Folder {
  /** Module-level const name -> possible values (only names declared exactly once in the file). */
  readonly candidates = new Map<string, Val[]>();
  constructor(private readonly ts: typeof tsType) {}

  /** Possible values of n; undefined when anything outside the pure subset is involved. */
  possible(n: tsType.Node, env: Map<string, Val>, unionUnknownConditions: boolean, d = 0): Val[] | undefined {
    const ts = this.ts;
    const K = ts.SyntaxKind;
    if (d > MAX_DEPTH) return undefined;
    while (ts.isParenthesizedExpression(n)) n = n.expression;
    const cart = (a: Val[], b: Val[], f: (x: Val, y: Val) => Val | undefined): Val[] | undefined => {
      const out = new Set<Val>();
      for (const x of a) for (const y of b) {
        const v = f(x, y);
        if (v === undefined) return undefined;
        out.add(v);
        if (out.size > MAX_VALUES) return undefined;
      }
      return [...out];
    };
    if (ts.isNumericLiteral(n)) return [Number(n.text)];
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return [n.text];
    if (n.kind === K.TrueKeyword) return [true];
    if (n.kind === K.FalseKeyword) return [false];
    if (ts.isIdentifier(n)) return env.has(n.text) ? [env.get(n.text)!] : undefined;
    if (ts.isPrefixUnaryExpression(n)) {
      const v = this.possible(n.operand, env, unionUnknownConditions, d + 1);
      if (!v) return undefined;
      const f: Record<number, (x: Val) => Val> = { [K.ExclamationToken]: (x) => !x, [K.MinusToken]: (x) => -Number(x), [K.PlusToken]: (x) => Number(x), [K.TildeToken]: (x) => ~Number(x) };
      const op = f[n.operator];
      return op ? [...new Set(v.map(op))] : undefined;
    }
    if (ts.isConditionalExpression(n)) {
      const c = this.possible(n.condition, env, unionUnknownConditions, d + 1);
      const t = () => this.possible(n.whenTrue, env, unionUnknownConditions, d + 1);
      const e = () => this.possible(n.whenFalse, env, unionUnknownConditions, d + 1);
      if (!c) {
        if (!unionUnknownConditions) return undefined;
        const a = t(), b = e();
        return a && b ? [...new Set([...a, ...b])].slice(0, MAX_VALUES + 1) : undefined;
      }
      if (c.every(Boolean)) return t();
      if (!c.some(Boolean)) return e();
      const a = t(), b = e();
      return a && b ? [...new Set([...a, ...b])] : undefined;
    }
    if (ts.isCallExpression(n) && n.arguments.length === 2) {
      const callee = n.expression;
      if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === 'Math' && callee.name.text === 'imul' && !env.has('Math')) {
        const a = this.possible(n.arguments[0]!, env, unionUnknownConditions, d + 1);
        const b = a && this.possible(n.arguments[1]!, env, unionUnknownConditions, d + 1);
        return a && b ? cart(a, b, (x, y) => Math.imul(Number(x), Number(y))) : undefined;
      }
      return undefined;
    }
    if (ts.isBinaryExpression(n)) {
      const a = this.possible(n.left, env, unionUnknownConditions, d + 1);
      const b = a && this.possible(n.right, env, unionUnknownConditions, d + 1);
      if (!a || !b) return undefined;
      const num = (f: (x: number, y: number) => Val) => cart(a, b, (x, y) => (typeof x === 'string' || typeof y === 'string' ? undefined : f(Number(x), Number(y))));
      switch (n.operatorToken.kind) {
        case K.PlusToken: return cart(a, b, (x, y) => (typeof x === 'string' || typeof y === 'string' ? String(x) + String(y) : Number(x) + Number(y)));
        case K.MinusToken: return num((x, y) => x - y);
        case K.AsteriskToken: return num((x, y) => x * y);
        case K.SlashToken: return num((x, y) => x / y);
        case K.PercentToken: return num((x, y) => x % y);
        case K.AmpersandToken: return num((x, y) => x & y);
        case K.BarToken: return num((x, y) => x | y);
        case K.CaretToken: return num((x, y) => x ^ y);
        case K.LessThanLessThanToken: return num((x, y) => x << y);
        case K.GreaterThanGreaterThanToken: return num((x, y) => x >> y);
        case K.GreaterThanGreaterThanGreaterThanToken: return num((x, y) => x >>> y);
        case K.LessThanToken: return num((x, y) => x < y);
        case K.GreaterThanToken: return num((x, y) => x > y);
        case K.LessThanEqualsToken: return num((x, y) => x <= y);
        case K.GreaterThanEqualsToken: return num((x, y) => x >= y);
        case K.EqualsEqualsEqualsToken: return cart(a, b, (x, y) => x === y);
        case K.ExclamationEqualsEqualsToken: return cart(a, b, (x, y) => x !== y);
        case K.AmpersandAmpersandToken: return cart(a, b, (x, y) => (x ? y : x));
        case K.BarBarToken: return cart(a, b, (x, y) => (x ? x : y));
      }
      return undefined;
    }
    return undefined;
  }

  /** Free candidate identifiers referenced under n (bounded walk). */
  private freeNames(n: tsType.Node): string[] {
    const out = new Set<string>();
    const st = [n];
    let seen = 0;
    while (st.length && seen++ < 4096) {
      const x = st.pop()!;
      if (this.ts.isIdentifier(x) && this.candidates.has(x.text)) out.add(x.text);
      x.forEachChild((c) => { st.push(c); });
    }
    return [...out];
  }

  /** The single value n takes under every candidate assignment, or undefined. */
  constant(n: tsType.Node): { value: Val; usesCandidates: boolean } | undefined {
    const r = this.values(n);
    return r && r.values.length === 1 ? { value: r.values[0]!, usesCandidates: r.usesCandidates } : undefined;
  }

  /** Every distinct value n takes across candidate assignments (each assignment must fold to one value). */
  values(n: tsType.Node): { values: Val[]; usesCandidates: boolean } | undefined {
    const names = this.freeNames(n);
    let assignments: Map<string, Val>[] = [new Map()];
    for (const name of names) {
      const next: Map<string, Val>[] = [];
      for (const env of assignments) for (const v of this.candidates.get(name)!) next.push(new Map(env).set(name, v));
      assignments = next;
      if (assignments.length > MAX_ASSIGNMENTS) return undefined;
    }
    const out = new Set<Val>();
    for (const env of assignments) {
      const vs = this.possible(n, env, false);
      if (!vs || vs.length !== 1) return undefined;
      out.add(vs[0]!);
    }
    return out.size ? { values: [...out], usesCandidates: names.length > 0 } : undefined;
  }
}

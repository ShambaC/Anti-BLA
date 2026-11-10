// Structural measurements over a TypeScript-compiler AST. Pure: no eval, no require of target code,
// no getter invocation. All traversals are iterative so hostile nesting cannot blow our stack.
import type tsType from 'typescript';

export interface JsJob {
  text: string;
  fileName: string;
  maxAstNodes: number;
}

export interface Site {
  start: number;
  end: number;
}

export interface JsMeasurements {
  nodeCount: number;
  nodeBudgetExhausted: boolean;
  parseDiagnostics: number;
  maxAstDepth: number;
  maxExpressionDepth: number;
  maxExpressionDepthSite: Site | null;
  ternary: { maxAlternatives: number; site: Site | null; chainsOver16: number; literalChains: number; maxLiteralAlternatives: number; literalSite: Site | null };
  concat: { maxCandidates: number; site: Site | null; maxByteCharge: number; byteSite: Site | null };
  getters: { total: number; rings: { names: string[]; site: Site }[] };
  alias: { largestTable: { name: string; properties: number; literalValues: number; dynamicReads: number; site: Site } | null };
  constantGuards: { count: number; sites: (Site & { value: string })[] };
  duplicateShapes: { functions: number; largestGroup: number; site: Site | null };
  imports: string[];
  exportsCount: number;
  dynamicCode: Site[];
  sourceMappingUrl: string | null;
}

const LITERAL_CAP = 4096; // candidate lengths tracked per concatenation (REA cap is 256 candidates)
const REA_PRIMITIVE_JSON_BYTES = 1_048_576; // from rea-agents 6.8.0 javascriptSemanticResourceLimits.ts

export function measure(ts: typeof tsType, job: JsJob): JsMeasurements {
  const K = ts.SyntaxKind;
  const kind = /\.(ts|mts|cts)$/i.test(job.fileName) ? ts.ScriptKind.TS : /\.tsx$/i.test(job.fileName) ? ts.ScriptKind.TSX : /\.jsx$/i.test(job.fileName) ? ts.ScriptKind.JSX : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(job.fileName, job.text, ts.ScriptTarget.Latest, true, kind);
  const site = (n: tsType.Node): Site => ({ start: n.getStart(sf), end: n.getEnd() });
  const unparen = (n: tsType.Node): tsType.Node => {
    while (ts.isParenthesizedExpression(n)) n = n.expression;
    return n;
  };

  const m: JsMeasurements = {
    nodeCount: 0,
    nodeBudgetExhausted: false,
    parseDiagnostics: (sf as unknown as { parseDiagnostics?: unknown[] }).parseDiagnostics?.length ?? 0,
    maxAstDepth: 0,
    maxExpressionDepth: 0,
    maxExpressionDepthSite: null,
    ternary: { maxAlternatives: 0, site: null, chainsOver16: 0, literalChains: 0, maxLiteralAlternatives: 0, literalSite: null },
    concat: { maxCandidates: 0, site: null, maxByteCharge: 0, byteSite: null },
    getters: { total: 0, rings: [] },
    alias: { largestTable: null },
    constantGuards: { count: 0, sites: [] },
    duplicateShapes: { functions: 0, largestGroup: 0, site: null },
    imports: [],
    exportsCount: 0,
    dynamicCode: [],
    sourceMappingUrl: null,
  };

  /** Literal alternatives of a ?: chain, or null when any leaf is not a literal. Iterative. */
  const literalLeaves = (root: tsType.Node): (string | number)[] | null => {
    const out: (string | number)[] = [];
    const st = [root];
    while (st.length) {
      const n = unparen(st.pop()!);
      if (ts.isConditionalExpression(n)) { st.push(n.whenFalse, n.whenTrue); continue; }
      if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) out.push(n.text);
      else if (ts.isNumericLiteral(n)) out.push(Number(n.text));
      else return null;
      if (out.length > LITERAL_CAP) return out;
    }
    return out;
  };
  const leafCount = (root: tsType.Node): number => {
    let c = 0;
    const st = [root];
    while (st.length) {
      const n = unparen(st.pop()!);
      if (ts.isConditionalExpression(n)) st.push(n.whenFalse, n.whenTrue);
      else c++;
    }
    return c;
  };

  // Safe evaluator for literal-only numeric/boolean guards. Returns undefined when not provably constant.
  const constValue = (root: tsType.Node): number | boolean | undefined => {
    let ops = 0;
    const ev = (n: tsType.Node, d: number): number | boolean | undefined => {
      if (d > 64) return undefined;
      n = unparen(n);
      if (ts.isNumericLiteral(n)) return Number(n.text);
      if (n.kind === K.TrueKeyword) return true;
      if (n.kind === K.FalseKeyword) return false;
      if (ts.isPrefixUnaryExpression(n)) {
        const v = ev(n.operand, d + 1);
        if (v === undefined) return undefined;
        switch (n.operator) {
          case K.ExclamationToken: return !v;
          case K.MinusToken: return -Number(v);
          case K.PlusToken: return Number(v);
          case K.TildeToken: return ~Number(v);
        }
        return undefined;
      }
      if (ts.isBinaryExpression(n)) {
        const a = ev(n.left, d + 1);
        const b = ev(n.right, d + 1);
        if (a === undefined || b === undefined) return undefined;
        ops++;
        const x = Number(a), y = Number(b);
        switch (n.operatorToken.kind) {
          case K.PlusToken: return x + y;
          case K.MinusToken: return x - y;
          case K.AsteriskToken: return x * y;
          case K.SlashToken: return x / y;
          case K.PercentToken: return x % y;
          case K.LessThanToken: return x < y;
          case K.GreaterThanToken: return x > y;
          case K.LessThanEqualsToken: return x <= y;
          case K.GreaterThanEqualsToken: return x >= y;
          case K.EqualsEqualsEqualsToken: case K.EqualsEqualsToken: return typeof a === typeof b ? a === b : x === y;
          case K.ExclamationEqualsEqualsToken: case K.ExclamationEqualsToken: return typeof a === typeof b ? a !== b : x !== y;
          case K.AmpersandAmpersandToken: return a ? b : a;
          case K.BarBarToken: return a ? a : b;
          case K.AmpersandToken: return x & y;
          case K.BarToken: return x | y;
          case K.CaretToken: return x ^ y;
        }
        return undefined;
      }
      return undefined;
    };
    const v = ev(root, 0);
    return ops > 0 ? v : undefined; // bare literals like `!0` / `while(true)` are idioms, not opaque guards
  };

  const shapeCounts = new Map<string, { count: number; site: Site }>();
  const tables = new Map<string, { properties: number; literalValues: number; site: Site }>();
  const dynamicReads = new Map<string, number>();

  interface Frame { node: tsType.Node; depth: number; exprDepth: number }
  const stack: Frame[] = [{ node: sf, depth: 0, exprDepth: 0 }];
  while (stack.length) {
    const { node, depth, exprDepth } = stack.pop()!;
    if (++m.nodeCount > job.maxAstNodes) { m.nodeBudgetExhausted = true; break; }
    if (depth > m.maxAstDepth) m.maxAstDepth = depth;
    const isExpr = ts.isExpression(node) && !ts.isIdentifier(node) && !ts.isLiteralExpression(node);
    const ed = isExpr ? exprDepth + 1 : ts.isFunctionLike(node) || ts.isBlock(node) ? 0 : exprDepth;
    if (ed > m.maxExpressionDepth) { m.maxExpressionDepth = ed; m.maxExpressionDepthSite = site(node); }

    const parent = node.parent;
    if (ts.isConditionalExpression(node)) {
      let p: tsType.Node | undefined = parent;
      while (p && ts.isParenthesizedExpression(p)) p = p.parent;
      const isRoot = !(p && ts.isConditionalExpression(p) && unparen(p.condition) !== unparen(node));
      if (isRoot) {
        const n = leafCount(node);
        if (n > 16) m.ternary.chainsOver16++;
        const lit = literalLeaves(node);
        if (lit) {
          m.ternary.literalChains++;
          const distinct = new Set(lit).size;
          if (distinct > m.ternary.maxLiteralAlternatives) { m.ternary.maxLiteralAlternatives = distinct; m.ternary.literalSite = site(node); }
        }
        if (n > m.ternary.maxAlternatives) { m.ternary.maxAlternatives = n; m.ternary.site = site(node); }
      }
      const g = constValue(node.condition);
      if (g !== undefined) recordGuard(node.condition, g);
    }
    if ((ts.isIfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) && node.expression) {
      const g = constValue(node.expression);
      if (g !== undefined) recordGuard(node.expression, g);
    }

    // Concatenation of literal ternary chains: candidate product and REA's addition byte charge.
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === K.PlusToken) {
      let p: tsType.Node | undefined = parent;
      while (p && ts.isParenthesizedExpression(p)) p = p.parent;
      const isRoot = !(p && ts.isBinaryExpression(p) && p.operatorToken.kind === K.PlusToken);
      if (isRoot) measureConcat(node);
    }

    if (ts.isGetAccessorDeclaration(node)) m.getters.total++;
    if (ts.isObjectLiteralExpression(node) || ts.isClassLike(node)) findGetterRings(node);

    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = unparen(node.initializer);
      if (ts.isObjectLiteralExpression(init) && init.properties.length >= 64) {
        const literalValues = init.properties.filter((p) => ts.isPropertyAssignment(p) && literalLeaves(p.initializer) !== null).length;
        tables.set(node.name.text, { properties: init.properties.length, literalValues, site: site(node) });
      }
    }
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression)) {
      const a = unparen(node.argumentExpression);
      if (!ts.isStringLiteral(a) && !ts.isNumericLiteral(a) && !ts.isNoSubstitutionTemplateLiteral(a)) {
        dynamicReads.set(node.expression.text, (dynamicReads.get(node.expression.text) ?? 0) + 1);
      }
    }

    if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) && node.body) {
      m.duplicateShapes.functions++;
      const shape = shapeOf(node.body);
      if (shape) {
        const e = shapeCounts.get(shape);
        if (e) e.count++;
        else shapeCounts.set(shape, { count: 1, site: site(node) });
      }
    }

    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) m.imports.push(node.moduleSpecifier.text);
    if (ts.isExportDeclaration(node) || ts.isExportAssignment(node) || (ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((x) => x.kind === K.ExportKeyword))) m.exportsCount++;
    if (ts.isCallExpression(node)) {
      const callee = unparen(node.expression);
      if (ts.isIdentifier(callee) && callee.text === 'require' && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) m.imports.push(node.arguments[0].text);
      if (callee.kind === K.ImportKeyword && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) m.imports.push(node.arguments[0].text);
      if (ts.isIdentifier(callee) && (callee.text === 'eval' || callee.text === 'Function') && m.dynamicCode.length < 50) m.dynamicCode.push(site(node));
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function' && m.dynamicCode.length < 50) m.dynamicCode.push(site(node));

    const kids: tsType.Node[] = [];
    node.forEachChild((c) => { kids.push(c); });
    for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i]!, depth: depth + 1, exprDepth: ed });
  }

  for (const [name, t] of tables) {
    const reads = dynamicReads.get(name) ?? 0;
    if (reads > 0 && (!m.alias.largestTable || t.properties > m.alias.largestTable.properties)) m.alias.largestTable = { name, properties: t.properties, literalValues: t.literalValues, dynamicReads: reads, site: t.site };
  }
  for (const v of shapeCounts.values()) if (v.count > m.duplicateShapes.largestGroup) { m.duplicateShapes.largestGroup = v.count; m.duplicateShapes.site = v.site; }
  m.imports = [...new Set(m.imports)].sort().slice(0, 200);
  const smu = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m.exec(job.text.slice(-4096));
  m.sourceMappingUrl = smu ? smu[1]!.slice(0, 2048) : null;
  return m;

  function recordGuard(expr: tsType.Node, value: number | boolean) {
    m.constantGuards.count++;
    if (m.constantGuards.sites.length < 10) m.constantGuards.sites.push({ ...site(expr), value: String(value) });
  }

  function measureConcat(root: tsType.Node) {
    const operands: tsType.Node[] = [];
    const st: tsType.Node[] = [root];
    while (st.length) {
      const n = unparen(st.pop()!);
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === K.PlusToken) st.push(n.right, n.left);
      else operands.push(n);
    }
    if (!operands.some((o) => ts.isConditionalExpression(o))) return;
    // Left-to-right addition like REA's inert evaluator; stop when an operand is not a literal set.
    let acc: (string | number)[] | null = null;
    let candidates = 0;
    let maxCharge = 0;
    for (const o of operands) {
      const set = literalLeaves(o);
      if (!set) { acc = null; continue; }
      if (acc === null) { acc = [...new Set(set)]; continue; }
      let charge = 0;
      for (const l of acc) for (const r of set) {
        if (typeof l !== 'string' && typeof r !== 'string') continue;
        charge += (String(l).length + String(r).length) * 6 + 2;
        if (charge > REA_PRIMITIVE_JSON_BYTES * 64) break;
      }
      if (charge > maxCharge) maxCharge = charge;
      const next: (string | number)[] = [];
      outer: for (const l of acc) for (const r of set) {
        next.push(typeof l === 'number' && typeof r === 'number' ? l + r : String(l) + String(r));
        if (next.length > LITERAL_CAP) break outer;
      }
      acc = [...new Set(next)];
      // > LITERAL_CAP means "at least this many"; REA's own cap is 256.
      candidates = acc.length;
      if (candidates > m.concat.maxCandidates) { m.concat.maxCandidates = candidates; m.concat.site = site(root); }
    }
    if (maxCharge > m.concat.maxByteCharge) { m.concat.maxByteCharge = maxCharge; m.concat.byteSite = site(root); }
  }

  function findGetterRings(container: tsType.Node) {
    const members: readonly tsType.Node[] = ts.isObjectLiteralExpression(container) ? container.properties : (container as tsType.ClassLikeDeclaration).members;
    const edges = new Map<string, { to: string; node: tsType.Node }>();
    for (const mem of members) {
      if (!ts.isGetAccessorDeclaration(mem) || !mem.body || mem.body.statements.length === 0) continue;
      const name = ts.isIdentifier(mem.name) || ts.isStringLiteral(mem.name) ? mem.name.text : null;
      // The getter's final return decides the next receiver; earlier statements are side effects.
      const s = mem.body.statements[mem.body.statements.length - 1]!;
      if (!name || !ts.isReturnStatement(s) || !s.expression) continue;
      const e = unparen(s.expression);
      let to: string | null = null;
      if (ts.isPropertyAccessExpression(e) && e.expression.kind === K.ThisKeyword) to = e.name.text;
      if (ts.isElementAccessExpression(e) && e.expression.kind === K.ThisKeyword && ts.isStringLiteral(e.argumentExpression)) to = e.argumentExpression.text;
      if (to) edges.set(name, { to, node: mem });
    }
    const done = new Set<string>();
    for (const start of edges.keys()) {
      if (done.has(start) || m.getters.rings.length >= 20) continue;
      const path: string[] = [];
      let cur: string | undefined = start;
      while (cur !== undefined && edges.has(cur) && !path.includes(cur) && !done.has(cur)) { path.push(cur); cur = edges.get(cur)!.to; }
      path.forEach((p) => done.add(p));
      if (cur !== undefined && path.includes(cur)) {
        const ring = path.slice(path.indexOf(cur));
        m.getters.rings.push({ names: ring.slice(0, 16), site: site(edges.get(ring[0]!)!.node) });
      }
    }
  }

  function shapeOf(body: tsType.Node): string | null {
    const kinds: number[] = [];
    const st = [body];
    while (st.length && kinds.length <= 400) {
      const n = st.pop()!;
      kinds.push(n.kind);
      const kids: tsType.Node[] = [];
      n.forEachChild((c) => { kids.push(c); });
      for (let i = kids.length - 1; i >= 0; i--) st.push(kids[i]!);
    }
    return kinds.length >= 30 && kinds.length <= 400 ? kinds.join(',') : null;
  }
}

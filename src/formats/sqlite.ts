// SQLite: header facts + schema catalog only. The target file is never opened by SQLite:
// a private temp copy is opened read-only with query_only and trusted_schema=OFF, no extensions,
// and only fixed catalog queries run (no SELECT on user tables, so generated columns are never evaluated).
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeFinding, preview } from '../core/findings.js';
import { byteRef } from '../core/provenance.js';
import type { AnalyzeContext, AnalyzerResult, EvidenceRef, Finding, SuggestedAction } from '../core/types.js';
import { markerFinding, scanSegments } from './generic.js';

const SQL_WORDS = new Set(['and', 'or', 'not', 'in', 'is', 'as', 'cast', 'case', 'when', 'then', 'else', 'end', 'exists', 'between', 'like', 'glob', 'regexp', 'match', 'collate', 'escape', 'select', 'from', 'where', 'values', 'over', 'filter', 'partition', 'references', 'check', 'default', 'primary', 'key', 'unique', 'foreign', 'generated', 'always', 'stored', 'virtual', 'table', 'index', 'on', 'using', 'constraint', 'null', 'integer', 'text', 'real', 'blob', 'numeric', 'varchar', 'char', 'decimal', 'int', 'any', 'boolean', 'date', 'datetime', 'float', 'double', 'character', 'nvarchar', 'nchar', 'varying', 'into', 'join', 'having', 'limit', 'offset', 'group', 'order', 'by', 'union', 'with', 'recursive', 'returning', 'set', 'update', 'insert', 'delete', 'replace', 'raise', 'distinct', 'all', 'window', 'range', 'rows', 'json_each', 'json_tree']);

/** Built-ins that exist only in some SQLite builds/versions; never treated as application-defined. */
const OPTIONAL_BUILTINS = new Set(['acos', 'acosh', 'asin', 'asinh', 'atan', 'atan2', 'atanh', 'ceil', 'ceiling', 'cos', 'cosh', 'degrees', 'exp', 'floor', 'ln', 'log', 'log10', 'log2', 'mod', 'pi', 'pow', 'power', 'radians', 'sin', 'sinh', 'sqrt', 'tan', 'tanh', 'trunc', 'unhex', 'concat', 'concat_ws', 'octet_length', 'timediff', 'format', 'printf', 'string_agg', 'unistr', 'unistr_quote', 'iif', 'if', 'median', 'percentile', 'percentile_cont', 'percentile_disc', 'jsonb', 'jsonb_extract', 'jsonb_object', 'jsonb_array', 'jsonb_set', 'jsonb_insert', 'jsonb_replace', 'jsonb_remove', 'jsonb_patch', 'jsonb_group_array', 'jsonb_group_object', 'json_pretty', 'regexp', 'soundex', 'load_extension']);

/** Function-call names in an SQL expression, skipping string literals, quoted identifiers and comments. */
export function sqlFunctionNames(expr: string): string[] {
  const cleaned = expr
    .replace(/'(?:[^']|'')*'/g, "''")
    .replace(/"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\]/g, 'x')
    .replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, ' ');
  const out = new Set<string>();
  for (const m of cleaned.matchAll(/([A-Za-z_][A-Za-z0-9_$]*)\s*\(/g)) {
    const n = m[1]!.toLowerCase();
    if (!SQL_WORDS.has(n)) out.add(n);
  }
  return [...out].sort();
}

/** Expressions inside `[GENERATED ALWAYS] AS ( ... )` in a CREATE TABLE statement. */
export function generatedExpressions(createSql: string): string[] {
  const out: string[] = [];
  const re = /\bAS\s*\(/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(createSql)) !== null) {
    let depth = 1, i = re.lastIndex;
    for (; i < createSql.length && depth > 0; i++) {
      const c = createSql[i];
      if (c === "'") { const j = createSql.indexOf("'", i + 1); i = j < 0 ? createSql.length : j; continue; }
      if (c === '(') depth++;
      else if (c === ')') depth--;
    }
    out.push(createSql.slice(re.lastIndex, i - 1));
    re.lastIndex = i;
  }
  return out;
}

interface Header {
  pageSize: number;
  writeVersion: number;
  readVersion: number;
  changeCounter: number;
  pageCount: number;
  versionValidFor: number;
  schemaFormat: number;
  textEncoding: number;
  sqliteVersion: number;
  problems: string[];
}

export function parseHeader(b: Buffer, fileSize: number): Header {
  const raw = b.readUInt16BE(16);
  const pageSize = raw === 1 ? 65536 : raw;
  const h: Header = {
    pageSize,
    writeVersion: b[18]!,
    readVersion: b[19]!,
    changeCounter: b.readUInt32BE(24),
    pageCount: b.readUInt32BE(28),
    versionValidFor: b.readUInt32BE(92),
    schemaFormat: b.readUInt32BE(44),
    textEncoding: b.readUInt32BE(56),
    sqliteVersion: b.readUInt32BE(96),
    problems: [],
  };
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) h.problems.push(`invalid page size ${raw}`);
  else if (fileSize % pageSize !== 0) h.problems.push(`file size ${fileSize} is not a multiple of page size ${pageSize}`);
  if (b[21] !== 64 || b[22] !== 32 || b[23] !== 32) h.problems.push('payload fraction bytes are not 64/32/32');
  // 0 is legal for a database with an empty schema.
  if (h.textEncoding > 3) h.problems.push(`invalid text encoding ${h.textEncoding}`);
  if (h.schemaFormat > 4) h.problems.push(`invalid schema format ${h.schemaFormat}`);
  if (h.changeCounter === h.versionValidFor && pageSize >= 512 && h.pageCount * pageSize !== fileSize) h.problems.push(`header page count ${h.pageCount} x ${pageSize} != file size ${fileSize}`);
  return h;
}

export async function analyzeSqlite(ctx: AnalyzeContext): Promise<AnalyzerResult> {
  const sha = ctx.sha256;
  const lp = ctx.logicalPath;
  const findings: Finding[] = [];
  const limitations: string[] = ['Schema catalog only: no user-table rows are read, so generated/virtual column values and view results are unknown.'];
  const unknowns: string[] = [`${lp}: row contents and computed column values (never evaluated).`];
  const actions: SuggestedAction[] = [];
  const hdrRef = (note: string): EvidenceRef => byteRef(sha, lp, 0, 100, note, 'format');
  if (ctx.bytes.length < 100) {
    findings.push(makeFinding({ rule: 'sqlite-truncated-header', classification: 'analysis-limitation', title: 'SQLite header truncated', observation: `${ctx.bytes.length} bytes; header needs 100.`, interpretation: 'Not a usable database.', confidence: 'high', evidence: [byteRef(sha, lp, 0, ctx.bytes.length, 'file', 'format')] }));
    return { status: 'failed', format: 'sqlite', formatConfidence: 'high', findings, limitations, unknowns, facts: {} };
  }
  const h = parseHeader(ctx.bytes, ctx.sizeBytes);
  const facts: Record<string, unknown> = { pageSize: h.pageSize, pageCount: h.pageCount, schemaFormat: h.schemaFormat, textEncoding: h.textEncoding, journal: h.readVersion === 2 ? 'wal' : 'rollback', sqliteVersionNumber: h.sqliteVersion };
  if (h.readVersion === 2) limitations.push('WAL-mode database: a -wal sidecar (if any) was not read; recent commits may be missing.');
  if (h.problems.length) {
    findings.push(makeFinding({ rule: 'sqlite-header-inconsistent', classification: 'analysis-limitation', title: 'SQLite header inconsistencies', observation: h.problems.join('; '), interpretation: 'Truncated, corrupted or crafted file. Not by itself evidence of BLA.', confidence: 'high', evidence: [hdrRef('database header')] }));
  }
  if (ctx.truncated) {
    limitations.push('Database larger than the read budget: catalog not opened.');
    unknowns.push(`${lp}: schema catalog.`);
    return { status: 'partial', format: 'sqlite', formatConfidence: 'high', findings, limitations, unknowns, facts };
  }

  const { DatabaseSync } = await import('node:sqlite');
  const dir = await mkdtemp(join(tmpdir(), 'anti-bla-sqlite-'));
  const copy = join(dir, 'copy.db');
  type Row = Record<string, unknown>;
  let schema: Row[] = [];
  const tableCols = new Map<string, Row[]>();
  const openErrors: string[] = [];
  let functionList: Set<string> | null = null;
  let sqliteVersion = 'unknown';
  try {
    // Copy the bytes already read (and budget-charged), so SQLite never touches the target path.
    await writeFile(copy, ctx.bytes, { flag: 'wx' });
    const db = new DatabaseSync(copy, { readOnly: true, enableForeignKeyConstraints: false, allowExtension: false } as ConstructorParameters<typeof DatabaseSync>[1]);
    try {
      db.exec('PRAGMA query_only = 1; PRAGMA trusted_schema = 0;');
      const cap = ctx.budget.limits.maxListEntries * 10;
      schema = db.prepare(`SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name LIMIT ${cap + 1}`).all() as Row[];
      if (schema.length > cap) { limitations.push(`Schema listing capped at ${cap} objects.`); schema = schema.slice(0, cap); }
      try { sqliteVersion = String((db.prepare('SELECT sqlite_version() AS v').get() as Row).v); } catch { /* keep unknown */ }
      try {
        functionList = new Set((db.prepare('SELECT DISTINCT name FROM pragma_function_list').all() as Row[]).map((r) => String(r.name).toLowerCase()));
      } catch { functionList = null; }
      for (const t of schema) {
        if (t.type !== 'table' || String(t.name).startsWith('sqlite_')) continue;
        try {
          tableCols.set(String(t.name), db.prepare('SELECT name, type, hidden FROM pragma_table_xinfo(?)').all(String(t.name)) as Row[]);
        } catch (e) {
          openErrors.push(`${preview(String(t.name), 60)}: ${preview((e as Error).message, 120)}`);
        }
      }
    } finally {
      db.close();
    }
  } catch (e) {
    openErrors.push(preview((e as Error).message, 200));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  if (schema.length === 0 && openErrors.length) {
    findings.push(makeFinding({ rule: 'sqlite-unreadable', classification: 'analysis-limitation', title: 'SQLite catalog could not be read', observation: openErrors.join('; '), interpretation: 'Catalog unknown; the file may be corrupt or encrypted.', confidence: 'high', evidence: [hdrRef('database header')] }));
    unknowns.push(`${lp}: schema catalog.`);
    return { status: 'partial', format: 'sqlite', formatConfidence: 'high', findings, limitations, unknowns, facts };
  }
  if (openErrors.length) limitations.push(`Column info unavailable for: ${openErrors.slice(0, 5).join('; ')}`);
  if (!functionList) limitations.push('pragma_function_list unavailable; function availability not checked.');

  const locate = (sql: string): EvidenceRef => {
    const i = ctx.bytes.indexOf(Buffer.from(sql, 'utf8'));
    return i >= 0 ? byteRef(sha, lp, i, i + Buffer.byteLength(sql), 'schema SQL (stored text)', 'format') : { kind: 'format', artifactSha256: sha, logicalPath: lp, note: 'schema SQL (spans overflow pages; byte range not located)' };
  };

  const traps: { table: string; columns: string[]; functions: string[]; ref: EvidenceRef }[] = [];
  let generatedCols = 0;
  for (const t of schema) {
    if (t.type !== 'table' || typeof t.sql !== 'string') continue;
    const cols = tableCols.get(String(t.name)) ?? [];
    const gen = cols.filter((c) => c.hidden === 2 || c.hidden === 3);
    generatedCols += gen.length;
    if (gen.length === 0) continue;
    const fns = generatedExpressions(t.sql).flatMap(sqlFunctionNames);
    const absent = functionList ? [...new Set(fns)].filter((f) => !functionList!.has(f)) : [];
    const optional = absent.filter((f) => OPTIONAL_BUILTINS.has(f));
    if (optional.length) limitations.push(`Generated columns of ${preview(String(t.name), 40)} use ${optional.join(', ')}: built-in in some SQLite builds but absent here (SQLite ${sqliteVersion}); not treated as application-defined.`);
    const missing = absent.filter((f) => !OPTIONAL_BUILTINS.has(f));
    if (missing.length) traps.push({ table: String(t.name), columns: gen.map((c) => String(c.name)), functions: missing, ref: locate(t.sql) });
  }
  const viewsNeedingFns: string[] = [];
  for (const v of schema) {
    if ((v.type !== 'view' && v.type !== 'trigger') || typeof v.sql !== 'string' || !functionList) continue;
    if (sqlFunctionNames(v.sql).some((f) => !functionList!.has(f) && !OPTIONAL_BUILTINS.has(f))) viewsNeedingFns.push(`${v.type} ${preview(String(v.name), 60)}`);
  }
  if (traps.length) {
    findings.push(makeFinding({
      rule: 'sqlite-generated-column-unknown-function',
      classification: 'resource-limit',
      title: 'Generated columns depend on functions this SQLite build lacks',
      observation: `${traps.length} table(s) define generated columns calling functions absent from a stock SQLite connection: ${traps.slice(0, 5).map((t) => `${preview(t.table, 40)}(${t.columns.slice(0, 4).map((c) => preview(c, 30)).join(',')}) -> ${t.functions.slice(0, 4).join(',')}()`).join('; ')}.`,
      limitations: [`Function availability was checked against this host's SQLite ${sqliteVersion}; another build may differ.`],
      interpretation: 'Any query that selects these columns (e.g. SELECT *) needs application-defined functions, so analyzers on a bare connection fail (REA: SQLite column-evaluation failure). The column values are unknowable without the application\'s function. Matches a BLA trap-column pattern; legitimate apps also register custom functions.',
      confidence: 'high',
      evidence: traps.slice(0, 10).map((t) => t.ref),
      nextSteps: ['Select only stored columns, or use REA schema_scope: "database" for declarations.', 'Report computed values as unknown; do not load extensions or emulate the function.'],
      metrics: { tables: traps.length },
    }));
    actions.push({
      kind: 'rea-tool',
      title: 'Read SQLite declarations without evaluating trap columns',
      rationale: 'REA\'s own remediation for column-evaluation failures: omit table and use schema_scope "database", or select readable columns.',
      operation: 'inspect_sqlite_database',
      parametersHint: { schema_scope: 'database' },
      prerequisites: ['Confirm the connected inspect_sqlite_database schema advertises schema_scope.'],
      risk: 'read-only',
      expectedBenefit: 'Stored declarations and readable columns with REA Evidence IDs (hypothesis).',
      exitCriterion: 'Stop if the question needs the computed values; they require the application\'s runtime.',
    });
  }
  if (viewsNeedingFns.length) {
    findings.push(makeFinding({ rule: 'sqlite-view-unknown-function', classification: 'reachability-unknown', title: 'Views/triggers reference unavailable functions', observation: viewsNeedingFns.slice(0, 10).join('; '), interpretation: 'Querying these objects needs application-defined functions; their results are unknown statically.', confidence: 'medium', evidence: [hdrRef('schema catalog')] }));
  }
  const allSql = schema.filter((s) => typeof s.sql === 'string').map((s) => s.sql as string);
  const segs = allSql.map((sql) => { const r = locate(sql); return { text: sql, byteStart: r.byteStart ?? 0 }; });
  const sc = scanSegments(segs, sha, lp, ctx.budget, 'schema SQL');
  findings.push(...sc.findings);
  const mf = markerFinding(sc.blaMarkers);
  if (mf) findings.push(mf);

  const count = (t: string) => schema.filter((s) => s.type === t).length;
  Object.assign(facts, {
    analyzerSqliteVersion: sqliteVersion,
    tables: count('table'),
    views: count('view'),
    indexes: count('index'),
    triggers: count('trigger'),
    generatedColumns: generatedCols,
    tableNames: schema.filter((s) => s.type === 'table').map((s) => preview(String(s.name), 80)).slice(0, ctx.budget.limits.maxListEntries),
    virtualTables: schema.filter((s) => typeof s.sql === 'string' && /^\s*CREATE\s+VIRTUAL\s+TABLE/i.test(s.sql)).length,
  });
  return { status: h.problems.length || openErrors.length ? 'partial' : 'complete', format: 'sqlite', formatConfidence: 'high', findings, limitations, unknowns, facts, suggestedActions: actions };
}

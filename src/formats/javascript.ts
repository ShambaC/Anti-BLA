import { Worker } from 'node:worker_threads';
import { makeFinding } from '../core/findings.js';
import { TextIndex, textRef } from '../core/provenance.js';
import { readBounded } from '../core/files.js';
import type { AnalyzeContext, AnalyzerResult, EvidenceRef, Finding, SuggestedAction } from '../core/types.js';
import { limit, limitSource } from '../rea/failure-catalog.js';
import { scanSegments, markerFinding } from './generic.js';
import type { JsMeasurements, Site } from './js-measure.js';

type WorkerReply = { ok: true; result: JsMeasurements } | { ok: false; error: string; stackExhausted: boolean };

/** One reusable parse worker; replaced after a timeout or crash so a hostile file cannot wedge the run. */
export class JsWorkerHost {
  private worker: Worker | null = null;
  constructor(private readonly heapMb: number) {}

  run(text: string, fileName: string, maxAstNodes: number, timeoutMs: number): Promise<WorkerReply | { ok: false; error: string; timedOut?: boolean; crashed?: boolean }> {
    const w = (this.worker ??= new Worker(new URL('./js-worker.js', import.meta.url), {
      resourceLimits: { maxOldGenerationSizeMb: this.heapMb, stackSizeMb: 8 },
    }));
    w.unref();
    return new Promise((resolve) => {
      const done = (r: Parameters<typeof resolve>[0], kill: boolean) => {
        clearTimeout(timer);
        w.off('message', onMsg);
        w.off('error', onErr);
        w.off('exit', onExit);
        if (kill) { void w.terminate(); this.worker = null; }
        resolve(r);
      };
      const onMsg = (r: WorkerReply) => done(r, false);
      const onErr = (e: Error) => done({ ok: false, error: `worker crashed: ${e.message}`.slice(0, 300), crashed: true }, true);
      const onExit = () => done({ ok: false, error: 'worker exited unexpectedly', crashed: true }, true);
      const timer = setTimeout(() => done({ ok: false, error: `parse exceeded ${timeoutMs} ms`, timedOut: true }, true), timeoutMs);
      w.on('message', onMsg);
      w.on('error', onErr);
      w.on('exit', onExit);
      w.postMessage({ text, fileName, maxAstNodes });
    });
  }

  async close(): Promise<void> {
    await this.worker?.terminate();
    this.worker = null;
  }
}

function decodeUtf8(bytes: Buffer): { text: string; valid: boolean } {
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), valid: true };
  } catch {
    return { text: bytes.toString('utf8'), valid: false };
  }
}

export async function analyzeJavaScript(ctx: AnalyzeContext, host: JsWorkerHost, format: 'javascript' | 'typescript'): Promise<AnalyzerResult> {
  const { text, valid } = decodeUtf8(ctx.bytes);
  const idx = new TextIndex(text);
  const sha = ctx.sha256;
  const lp = ctx.logicalPath;
  const ref = (s: Site, note?: string): EvidenceRef => textRef(sha, lp, idx, s.start, s.end, note);
  const limitations: string[] = ['Reachability of functions and branches is not established: no trusted entrypoint graph is built.'];
  const unknowns: string[] = [`${lp}: runtime behavior, dynamic property targets and getter results (never evaluated).`];
  if (!valid) limitations.push('Invalid UTF-8: bytes were decoded with replacement characters; byte offsets after the first invalid sequence may be shifted.');
  if (ctx.truncated) limitations.push(`Only the first ${ctx.bytes.length} of ${ctx.sizeBytes} bytes were read (budget); parse covers a prefix only.`);

  const scan = scanSegments([{ text, byteStart: 0, index: idx }], sha, lp, ctx.budget, 'source text, comments and string literals');
  const findings: Finding[] = [...scan.findings];
  const mf = markerFinding(scan.blaMarkers);
  if (mf) findings.push(mf);

  const reply = await host.run(text, lp, ctx.budget.limits.maxAstNodes, Math.min(ctx.budget.limits.jsParseTimeoutMs, Math.max(1, ctx.budget.remainingMs())));
  if (!reply.ok) {
    findings.push(
      makeFinding({
        rule: 'js-parse-incomplete',
        classification: 'analysis-limitation',
        title: 'JavaScript parse did not complete within Anti-BLA limits',
        observation: reply.error,
        interpretation: 'A parser failure or timeout is a property of this inspection, not evidence of BLA. Structural metrics for this file are unknown.',
        confidence: 'high',
        evidence: [{ kind: 'bytes', artifactSha256: sha, logicalPath: lp, byteStart: 0, byteEnd: ctx.bytes.length, note: 'whole inspected prefix' }],
        nextSteps: ['Use REA analyze_javascript_application with source_paths narrowed to this file if the question needs it.'],
      }),
    );
    unknowns.push(`${lp}: all AST-level structure (parse incomplete).`);
    return { status: 'partial', format, formatConfidence: 'medium', findings, limitations, unknowns, facts: { parse: 'incomplete' } };
  }
  const m = reply.result;
  let status: AnalyzerResult['status'] = ctx.truncated || m.nodeBudgetExhausted ? 'partial' : 'complete';
  if (m.parseDiagnostics > 0) {
    status = 'partial';
    limitations.push(`Parser recovered from ${m.parseDiagnostics} syntax error(s); structure near those points is approximate.`);
  }
  if (m.nodeBudgetExhausted) limitations.push(`AST walk stopped at ${ctx.budget.limits.maxAstNodes} nodes.`);

  const candLimit = limit('js.primitiveCandidates');
  const lit = Math.max(m.ternary.maxLiteralAlternatives, m.concat.maxCandidates);
  if (lit > candLimit) {
    const s = (m.concat.maxCandidates >= m.ternary.maxLiteralAlternatives ? m.concat.site : m.ternary.literalSite)!;
    findings.push(
      makeFinding({
        rule: 'js-literal-alternative-explosion',
        classification: 'resource-limit',
        title: 'Literal alternatives exceed REA primitive-candidate budget',
        observation: `A ?: chain / concatenation yields at least ${lit} distinct literal alternatives (largest single chain: ${m.ternary.maxLiteralAlternatives}; concatenation product: ${m.concat.maxCandidates}).`,
        interpretation: `REA's inert evaluator keeps at most ${candLimit} alternatives (${limitSource('js.primitiveCandidates')}); this value is expected to come back as unknown with resourceLimit "primitive-candidates". This matches a BLA-style candidate-explosion pattern but is not attribution.`,
        confidence: 'high',
        evidence: [ref(s, 'expression root')],
        limitations: ['Candidate count uses JS addition semantics over literal leaves only; non-literal leaves end the count.'],
        nextSteps: ['Confirm with REA\'s own semantic unknowns before claiming the budget was hit.', 'Answer the question from other evidence; do not raise limits repeatedly.'],
        metrics: { distinctAlternatives: lit, reaLimit: candLimit },
      }),
    );
  }
  const byteLimit = limit('js.primitiveBytes');
  if (m.concat.maxByteCharge > byteLimit && m.concat.byteSite) {
    findings.push(
      makeFinding({
        rule: 'js-primitive-byte-charge',
        classification: 'resource-limit',
        title: 'String concatenation exceeds REA primitive-byte budget',
        observation: `One literal-set addition is charged ${m.concat.maxByteCharge} bytes under REA's (len(l)+len(r))*6+2 formula.`,
        interpretation: `REA bounds this at ${byteLimit} bytes (${limitSource('js.primitiveBytes')}); expect unknown("primitive-bytes").`,
        confidence: 'high',
        evidence: [ref(m.concat.byteSite, 'concatenation root')],
        metrics: { byteCharge: m.concat.maxByteCharge, reaLimit: byteLimit },
      }),
    );
  }
  const depthLimit = limit('js.expressionDepth');
  if (m.maxExpressionDepth > depthLimit && m.maxExpressionDepthSite) {
    findings.push(
      makeFinding({
        rule: 'js-expression-depth',
        classification: 'resource-limit',
        title: 'Expression nesting deeper than REA semantic depth budget',
        observation: `Maximum nested expression depth measured: ${m.maxExpressionDepth}.`,
        interpretation: `REA bounds active expression nesting at ${depthLimit} (${limitSource('js.expressionDepth')}). Anti-BLA's depth count is not identical to REA's, so treat as likely, not certain.`,
        confidence: 'medium',
        evidence: [ref(m.maxExpressionDepthSite, 'deepest expression')],
        metrics: { depth: m.maxExpressionDepth, reaLimit: depthLimit },
      }),
    );
  }
  if (m.getters.rings.length > 0) {
    findings.push(
      makeFinding({
        rule: 'js-getter-ring',
        classification: 'resource-limit',
        title: 'Self-referential getter ring(s)',
        observation: `${m.getters.rings.length} getter cycle(s) of the form get a(){return this.b} (first: ${m.getters.rings[0]!.names.join(' -> ')}). Getters were not invoked.`,
        interpretation: `Reading such a property would recurse at runtime; static evaluators bound it (REA getter-expansion ${limit('js.getterExpansion')}, ${limitSource('js.getterExpansion')}). Likely an analysis trap or dead code; reachability unknown.`,
        confidence: 'medium',
        evidence: m.getters.rings.slice(0, 10).map((r) => ref(r.site, `ring: ${r.names.join(' -> ')}`)),
        metrics: { rings: m.getters.rings.length, getters: m.getters.total },
      }),
    );
  }
  const aliasLimit = limit('js.aliasSelections');
  const t = m.alias.largestTable;
  if (t && t.properties > aliasLimit) {
    findings.push(
      makeFinding({
        rule: 'js-alias-table',
        classification: 'resource-limit',
        title: 'Large table read through dynamic keys',
        observation: `Object literal "${t.name}" has ${t.properties} properties (${t.literalValues} with literal values) and ${t.dynamicReads} dynamic-key read(s) (${t.name}[expr]).`,
        interpretation: `Selecting through more than ${aliasLimit} possible properties exceeds REA's alias-selection budget (${limitSource('js.aliasSelections')}); selected paths are expected to stay unknown.`,
        // Lookup tables of non-literal values (e.g. diagnostic registries) are common in real code.
        confidence: t.literalValues >= t.properties * 0.9 ? 'medium' : 'low',
        evidence: [ref(t.site, 'table declaration')],
        metrics: { properties: t.properties, literalValues: t.literalValues, dynamicReads: t.dynamicReads, reaLimit: aliasLimit },
      }),
    );
  }
  if (m.constantGuards.count > 0) {
    findings.push(
      makeFinding({
        rule: 'js-constant-guard',
        classification: 'possible-decoy',
        title: 'Branch guards that are constant under JS numeric semantics',
        observation: `${m.constantGuards.count} condition(s) built only from numeric/boolean literals evaluate to a constant (e.g. ${m.constantGuards.sites.slice(0, 3).map((g) => g.value).join(', ')}).`,
        interpretation: 'As written, one arm of each such branch cannot execute. Code in the dead arm is not evidence of behavior. Do not delete it: the guard could change if the code is modified at runtime.',
        confidence: 'high',
        evidence: m.constantGuards.sites.map((g) => ref(g, `guard evaluates to ${g.value}`)),
        limitations: ['Only literal-only guards are evaluated; opaque predicates over variables are not proven.'],
        metrics: { guards: m.constantGuards.count },
      }),
    );
  }
  if (m.duplicateShapes.largestGroup >= 50 && m.duplicateShapes.largestGroup >= m.duplicateShapes.functions * 0.1 && m.duplicateShapes.site) {
    findings.push(
      makeFinding({
        rule: 'js-duplicate-function-shapes',
        classification: 'possible-decoy',
        title: 'Many structurally identical function bodies',
        observation: `${m.duplicateShapes.largestGroup} of ${m.duplicateShapes.functions} function bodies share one syntax shape (30-400 nodes, names/literals ignored).`,
        interpretation: 'Synthetic volume (chaff, call-graph labyrinths) often repeats a template; generated code can also do this legitimately.',
        confidence: 'low',
        evidence: [ref(m.duplicateShapes.site, 'first instance')],
        metrics: { group: m.duplicateShapes.largestGroup, functions: m.duplicateShapes.functions },
      }),
    );
  }
  if (m.dynamicCode.length > 0) {
    findings.push(
      makeFinding({
        rule: 'js-dynamic-code',
        classification: 'reachability-unknown',
        title: 'Dynamic code construction sites',
        observation: `${m.dynamicCode.length} eval/Function call site(s).`,
        interpretation: 'Code generated at runtime is invisible to static analysis; behavior there is unknown, not absent.',
        confidence: 'high',
        evidence: m.dynamicCode.slice(0, 10).map((s) => ref(s)),
      }),
    );
    unknowns.push(`${lp}: code produced by eval/Function at runtime.`);
  }

  const suggestedActions: SuggestedAction[] = [];
  if (findings.some((f) => f.classification === 'resource-limit')) {
    suggestedActions.push({
      kind: 'rea-tool',
      title: `Scope REA JavaScript analysis to ${lp} and read retained partial facts`,
      rationale: 'Resource-limit structures inflate whole-application semantic analysis; selected source paths keep the inventory complete and the question focused.',
      operation: 'analyze_javascript_application',
      parametersHint: { source_paths: [lp], detail: 'summary' },
      prerequisites: ['Confirm the connected tools/list schema advertises source_paths and detail.', 'Use the exact inventoried path REA reports, which may differ from this logical path.'],
      risk: 'read-only',
      expectedBenefit: 'Completed static facts for the selected file, with specific unknown scopes instead of a whole-app failure (hypothesis).',
      exitCriterion: 'Stop if REA reports the same resource limit for the same scope; report the value as unknown.',
    });
  }

  let sourceMap: Record<string, unknown> | null = null;
  if (m.sourceMappingUrl) {
    sourceMap = { url: m.sourceMappingUrl.startsWith('data:') ? 'inline data: URL' : m.sourceMappingUrl };
    if (m.sourceMappingUrl.startsWith('data:')) {
      const comma = m.sourceMappingUrl.indexOf(',');
      const b64 = /;base64$/i.test(m.sourceMappingUrl.slice(0, comma));
      const raw = m.sourceMappingUrl.slice(comma + 1);
      const json = b64 ? Buffer.from(raw, 'base64').toString('utf8') : decodeURIComponent(raw);
      const r = analyzeSourceMapText(json, ctx, text, `${lp}#inline-sourcemap`);
      findings.push(...r.findings);
      limitations.push(...r.limitations);
    }
  }

  return {
    status,
    format,
    formatConfidence: 'medium',
    findings,
    limitations,
    unknowns,
    suggestedActions,
    facts: {
      nodes: m.nodeCount,
      maxAstDepth: m.maxAstDepth,
      maxExpressionDepth: m.maxExpressionDepth,
      maxTernaryAlternatives: m.ternary.maxAlternatives,
      literalTernaryChains: m.ternary.literalChains,
      getters: m.getters.total,
      functions: m.duplicateShapes.functions,
      imports: m.imports,
      exports: m.exportsCount,
      sourceMap,
    },
  };
}

// ---------------- Source maps ----------------

const B64 = new Map([...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'].map((c, i) => [c, i]));
const MAX_SEGMENTS = 5_000_000;

export interface DecodedMappings {
  valid: boolean;
  error?: string;
  segments: number;
  truncated: boolean;
  generatedLines: number;
  referencedSources: Set<number>;
  minSource: number;
  maxSource: number;
  lineMaxColumn: number[];
}

/** Source Map v3 base64-VLQ decoder, bounded by MAX_SEGMENTS. */
export function decodeMappings(mappings: string): DecodedMappings {
  const out: DecodedMappings = { valid: true, segments: 0, truncated: false, generatedLines: 1, referencedSources: new Set(), minSource: 0, maxSource: -1, lineMaxColumn: [0] };
  let genCol = 0, src = 0;
  let fields: number[] = [];
  let value = 0, shift = 0, inValue = false;
  const endSegment = () => {
    if (inValue) { out.valid = false; out.error = 'unterminated VLQ value'; }
    if (fields.length === 0) return;
    if (![1, 4, 5].includes(fields.length)) { out.valid = false; out.error ??= `segment with ${fields.length} fields`; }
    genCol += fields[0]!;
    const line = out.generatedLines - 1;
    if (genCol > out.lineMaxColumn[line]!) out.lineMaxColumn[line] = genCol;
    if (fields.length >= 4) {
      src += fields[1]!;
      out.referencedSources.add(src);
      if (src < out.minSource) out.minSource = src;
      if (src > out.maxSource) out.maxSource = src;
    }
    out.segments++;
    fields = [];
  };
  for (let i = 0; i < mappings.length; i++) {
    const c = mappings[i]!;
    if (c === ',' || c === ';') {
      endSegment();
      if (c === ';') { out.generatedLines++; out.lineMaxColumn.push(0); genCol = 0; }
      if (out.segments >= MAX_SEGMENTS) { out.truncated = true; break; }
      continue;
    }
    const d = B64.get(c);
    if (d === undefined) { out.valid = false; out.error = `invalid base64 character at ${i}`; break; }
    inValue = true;
    value += (d & 31) * 2 ** shift;
    shift += 5;
    if (shift > 35) { out.valid = false; out.error = `VLQ value too long at ${i}`; break; }
    if ((d & 32) === 0) {
      const neg = value % 2 === 1;
      const v = Math.floor(value / 2);
      fields.push(neg ? -v : v);
      value = 0; shift = 0; inValue = false;
    }
  }
  if (out.valid && !out.truncated) endSegment();
  return out;
}

export function analyzeSourceMap(ctx: AnalyzeContext): AnalyzerResult {
  const { text } = decodeUtf8(ctx.bytes);
  const r = analyzeSourceMapText(text, ctx, undefined, ctx.logicalPath);
  return { status: r.status, format: 'source-map', formatConfidence: 'medium', findings: r.findings, limitations: r.limitations, unknowns: r.unknowns, facts: r.facts };
}

interface MapAnalysis {
  status: AnalyzerResult['status'];
  findings: Finding[];
  limitations: string[];
  unknowns: string[];
  facts: Record<string, unknown>;
}

function analyzeSourceMapText(text: string, ctx: AnalyzeContext, bundleText: string | undefined, lp: string): MapAnalysis {
  const sha = ctx.sha256;
  const limitations = ['sourcesContent and sources are developer-provided assertions; they are not verified to be the original source.'];
  const unknowns: string[] = [];
  const findings: Finding[] = [];
  const at = (pointer: string, note?: string): EvidenceRef => ({ kind: 'format', artifactSha256: sha, logicalPath: lp, jsonPointer: pointer, ...(note ? { note } : {}) });
  let map: { version?: unknown; sources?: unknown; sourcesContent?: unknown; mappings?: unknown; file?: unknown; sections?: unknown };
  try {
    map = JSON.parse(text);
  } catch (e) {
    findings.push(makeFinding({ rule: 'sourcemap-malformed', classification: 'analysis-limitation', title: 'Source map is not valid JSON', observation: (e as Error).message.slice(0, 200), interpretation: 'Malformed maps carry no mapping evidence.', confidence: 'high', evidence: [at('', 'whole file')] }));
    return { status: 'failed', findings, limitations, unknowns, facts: {} };
  }
  if (map === null || typeof map !== 'object' || Array.isArray(map)) map = {};
  if (map.sections !== undefined) {
    unknowns.push(`${lp}: indexed (sectioned) source map not analyzed.`);
    return { status: 'unsupported', findings, limitations, unknowns, facts: { version: map.version, sectioned: true } };
  }
  const sources = Array.isArray(map.sources) ? map.sources : [];
  const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
  const mappings = typeof map.mappings === 'string' ? map.mappings : '';
  const problems: string[] = [];
  if (map.version !== 3) problems.push(`version is ${JSON.stringify(map.version)}, not 3`);
  if (!Array.isArray(map.sources)) problems.push('sources is not an array');
  if (typeof map.mappings !== 'string') problems.push('mappings is not a string');
  const dec = decodeMappings(mappings);
  if (!dec.valid) problems.push(`mappings: ${dec.error}`);
  if (dec.truncated) limitations.push(`Mapping decode stopped after ${MAX_SEGMENTS} segments.`);
  if (problems.length) {
    findings.push(makeFinding({ rule: 'sourcemap-malformed', classification: 'analysis-limitation', title: 'Source map structure is invalid', observation: problems.join('; '), interpretation: 'Invalid structure means mapping claims cannot be checked.', confidence: 'high', evidence: [at('', 'top-level fields')] }));
  }
  if (contents.length > 0 && contents.length !== sources.length) {
    findings.push(makeFinding({ rule: 'sourcemap-content-count-mismatch', classification: 'possible-decoy', title: 'sourcesContent length differs from sources', observation: `${contents.length} sourcesContent entries vs ${sources.length} sources.`, interpretation: 'Content cannot be reliably paired with source names.', confidence: 'medium', evidence: [at('/sourcesContent')] }));
  }
  if (dec.maxSource >= sources.length || dec.minSource < 0) {
    findings.push(makeFinding({ rule: 'sourcemap-index-out-of-range', classification: 'possible-decoy', title: 'Mappings reference nonexistent sources', observation: `Source indices range ${dec.minSource}..${dec.maxSource} but only ${sources.length} sources are declared.`, interpretation: 'The map is internally inconsistent; do not trust its source attribution.', confidence: 'high', evidence: [at('/mappings')] }));
  }
  const unreferenced: number[] = [];
  contents.forEach((c, i) => { if (typeof c === 'string' && c.length > 0 && !dec.referencedSources.has(i)) unreferenced.push(i); });
  if (unreferenced.length > 0) {
    findings.push(makeFinding({
      rule: 'sourcemap-unreferenced-content',
      classification: 'possible-decoy',
      title: 'Embedded source content that no mapping points to',
      observation: `${unreferenced.length} of ${contents.length} sourcesContent entries are never referenced by any mapping segment (e.g. ${unreferenced.slice(0, 5).map((i) => JSON.stringify(String(sources[i] ?? i).slice(0, 80))).join(', ')}).`,
      interpretation: 'Unreferenced content does not correspond to any emitted code; it may be a honey source or stale. Do not describe it as the shipped implementation.',
      confidence: 'medium',
      evidence: unreferenced.slice(0, 10).map((i) => at(`/sourcesContent/${i}`)),
      metrics: { unreferenced: unreferenced.length },
    }));
  }
  if (bundleText !== undefined) {
    const lines = bundleText.split('\n');
    let lineOverflow = 0, colOverflow = 0;
    for (let l = 0; l < dec.lineMaxColumn.length; l++) {
      const hasSegs = dec.lineMaxColumn[l]! > 0;
      if (l >= lines.length) { if (hasSegs) lineOverflow++; continue; }
      if (dec.lineMaxColumn[l]! > lines[l]!.length) colOverflow++;
    }
    if (lineOverflow + colOverflow > 0) {
      findings.push(makeFinding({
        rule: 'sourcemap-bundle-mismatch',
        classification: 'possible-decoy',
        title: 'Source map does not fit the emitted bundle',
        observation: `${lineOverflow} mapped generated line(s) beyond the bundle's ${lines.length} lines; ${colOverflow} line(s) with mapped columns beyond line length.`,
        interpretation: 'The map was not generated for this bundle (or was altered). Its sources are unverified claims, not the shipped code.',
        confidence: 'high',
        evidence: [at('/mappings'), { kind: 'derived', note: 'compared against paired bundle line lengths' }],
        metrics: { lineOverflow, colOverflow, bundleLines: lines.length },
      }));
    }
  } else {
    unknowns.push(`${lp}: whether mappings fit the emitted bundle (bundle not provided in this scan).`);
  }
  return {
    status: problems.length ? 'partial' : 'complete',
    findings,
    limitations,
    unknowns,
    facts: { version: map.version, sources: sources.length, sourcesContent: contents.length, segments: dec.segments, generatedLines: dec.generatedLines, file: typeof map.file === 'string' ? map.file.slice(0, 200) : null },
  };
}

/** Pair a source map with its bundle inside the same scan and re-run the fit check. */
export async function analyzeSourceMapWithBundle(ctx: AnalyzeContext): Promise<AnalyzerResult> {
  const base = analyzeSourceMap(ctx);
  if (base.status === 'failed' || !ctx.sibling) return base;
  const file = typeof base.facts.file === 'string' ? base.facts.file : ctx.logicalPath.replace(/\.map$/i, '');
  const dir = ctx.logicalPath.includes('/') ? ctx.logicalPath.slice(0, ctx.logicalPath.lastIndexOf('/') + 1) : '';
  const candidate = ctx.sibling(dir + file.split(/[\\/]/).pop()!);
  if (!candidate) return base;
  const { size } = await import('node:fs/promises').then((f) => f.stat(candidate));
  const { bytes, truncated } = await readBounded(candidate, size, ctx.budget);
  if (truncated) {
    base.unknowns.push(`${ctx.logicalPath}: bundle fit not checked (paired bundle exceeded read budget).`);
    return base;
  }
  const r = analyzeSourceMapText(decodeUtf8(ctx.bytes).text, ctx, decodeUtf8(bytes).text, ctx.logicalPath);
  r.facts.pairedBundle = dir + file.split(/[\\/]/).pop()!;
  return { status: r.status, format: 'source-map', formatConfidence: 'medium', findings: r.findings, limitations: r.limitations, unknowns: r.unknowns, facts: r.facts };
}

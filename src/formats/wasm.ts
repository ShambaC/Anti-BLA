// WebAssembly binary inventory. Bounded LEB128, no allocation driven by declared counts,
// never instantiated. WebAssembly.validate only compiles/validates; it runs no module code.
import { makeFinding, preview } from '../core/findings.js';
import { byteRef } from '../core/provenance.js';
import type { AnalyzeContext, AnalyzerResult, Finding, SuggestedAction } from '../core/types.js';
import { limit, limitSource } from '../rea/failure-catalog.js';
import { asciiSegments, markerFinding, scanSegments } from './generic.js';

class WasmError extends Error {
  constructor(message: string, readonly offset: number) { super(message); }
}

class Reader {
  constructor(readonly b: Buffer, public pos: number, readonly end: number) {}
  byte(): number {
    if (this.pos >= this.end) throw new WasmError('unexpected end of section', this.pos);
    return this.b[this.pos++]!;
  }
  /** Unsigned LEB128 up to `maxBits` (32 or 64); rejects over-long encodings. */
  leb(maxBits = 32): number {
    let result = 0, shift = 0;
    const start = this.pos;
    const maxBytes = Math.ceil(maxBits / 7);
    for (let i = 0; i < maxBytes; i++) {
      const byte = this.byte();
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) {
        if (result > 2 ** maxBits - 1 || !Number.isSafeInteger(result)) throw new WasmError('LEB128 value out of range', start);
        return result;
      }
      shift += 7;
    }
    throw new WasmError('LEB128 encoding too long', start);
  }
  name(): string {
    const len = this.leb();
    if (len > this.end - this.pos) throw new WasmError(`name length ${len} exceeds section`, this.pos);
    const s = this.b.subarray(this.pos, this.pos + len);
    this.pos += len;
    return new TextDecoder('utf-8', { fatal: false }).decode(s);
  }
  limits(): void {
    const flags = this.byte();
    const bits = flags & 4 ? 64 : 32;
    this.leb(bits);
    if (flags & 1) this.leb(bits);
  }
}

const MAX_SECTIONS = 10_000;
const ORDER: Record<number, number> = { 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8, 8: 9, 9: 10, 12: 11, 10: 12, 11: 13 };
const SECTION_NAMES: Record<number, string> = { 0: 'custom', 1: 'type', 2: 'import', 3: 'function', 4: 'table', 5: 'memory', 6: 'global', 7: 'export', 8: 'start', 9: 'element', 10: 'code', 11: 'data', 12: 'datacount', 13: 'tag' };
const TOOLCHAIN_CUSTOM = /^(name|producers|target_features|sourceMappingURL|external_debug_info|linking|dylink(\.0)?|reloc\..*|\.debug_.*|metadata\.code\..*|build_id)$/;
const KIND = ['func', 'table', 'memory', 'global', 'tag'];

export async function analyzeWasm(ctx: AnalyzeContext): Promise<AnalyzerResult> {
  const sha = ctx.sha256;
  const lp = ctx.logicalPath;
  const b = ctx.bytes;
  const findings: Finding[] = [];
  const limitations: string[] = ['Module is never instantiated; exports are not shown to be reachable from any host JavaScript.'];
  const unknowns: string[] = [];
  const actions: SuggestedAction[] = [];
  const maxList = ctx.budget.limits.maxListEntries;

  if (ctx.truncated) limitations.push(`Only the first ${b.length} of ${ctx.sizeBytes} bytes were read (budget); later sections unknown.`);
  if (b.length < 8 || b.readUInt32BE(0) !== 0x0061736d) {
    findings.push(makeFinding({ rule: 'wasm-bad-header', classification: 'analysis-limitation', title: 'Not a WebAssembly binary header', observation: `First bytes: ${b.subarray(0, 8).toString('hex')}.`, interpretation: 'Cannot be parsed as WASM.', confidence: 'high', evidence: [byteRef(sha, lp, 0, Math.min(8, b.length), 'header', 'format')] }));
    return { status: 'failed', format: 'wasm', formatConfidence: 'high', findings, limitations, unknowns, facts: {} };
  }
  const version = b.readUInt32LE(4);
  if (version !== 1) {
    unknowns.push(`${lp}: version/layer 0x${version.toString(16)} (component model or future format) not decoded.`);
    return { status: 'unsupported', format: 'wasm', formatConfidence: 'high', findings, limitations, unknowns, facts: { version } };
  }

  const sections: { id: number; name: string; start: number; end: number; customName?: string }[] = [];
  const imports: { module: string; name: string; kind: string }[] = [];
  const exports: { name: string; kind: string }[] = [];
  let importCount = 0, exportCount = 0, typeCount = 0, funcCount = 0, codeCount = 0;
  let nameBytes = 0, reaChargeLowerBound = 0;
  const exportNames = new Set<string>();
  const dupExports: string[] = [];
  const structural: { msg: string; offset: number }[] = [];
  let lastRank = 0;
  const seenIds = new Set<number>();
  let pos = 8;
  let parseError: WasmError | null = null;
  let sectionsNotListed = 0;
  let structuralCount = 0;
  // Bounded bookkeeping: a hostile module can declare millions of empty sections.
  const pushStructural = (x: { msg: string; offset: number }) => { structuralCount++; if (structural.length < 100) structural.push(x); };

  try {
    while (pos < b.length) {
      if (ctx.budget.timedOut()) { ctx.budget.markTruncated('time budget exhausted in WASM parse'); limitations.push('Time budget exhausted mid-module.'); break; }
      const top = new Reader(b, pos, b.length);
      const id = top.byte();
      const size = top.leb();
      const start = top.pos;
      if (size > b.length - start) {
        if (ctx.truncated) { limitations.push(`Section ${id} at ${pos} extends past the read prefix.`); break; }
        throw new WasmError(`section ${id} declares ${size} bytes but only ${b.length - start} remain`, pos);
      }
      const end = start + size;
      const sec: (typeof sections)[number] = { id, name: SECTION_NAMES[id] ?? `unknown(${id})`, start: pos, end };
      if (id !== 0) {
        const rank = ORDER[id];
        if (rank === undefined) pushStructural({ msg: `unknown section id ${id}`, offset: pos });
        else {
          if (seenIds.has(id)) pushStructural({ msg: `duplicate ${sec.name} section`, offset: pos });
          else if (rank < lastRank) pushStructural({ msg: `${sec.name} section out of order`, offset: pos });
          seenIds.add(id);
          lastRank = Math.max(lastRank, rank);
        }
      }
      const r = new Reader(b, start, end);
      switch (id) {
        case 0: sec.customName = r.name(); break;
        case 1: typeCount = r.leb(); break;
        case 3: funcCount = r.leb(); break;
        case 10: codeCount = r.leb(); break;
        case 2: {
          const n = r.leb();
          if (n > size) throw new WasmError(`import count ${n} impossible in ${size} bytes`, start);
          for (let i = 0; i < n; i++) {
            const module = r.name();
            const name = r.name();
            const k = r.byte();
            if (k === 0) r.leb(); else if (k === 1) { r.byte(); r.limits(); } else if (k === 2) r.limits(); else if (k === 3) { r.byte(); r.byte(); } else if (k === 4) { r.byte(); r.leb(); } else throw new WasmError(`import kind ${k}`, r.pos - 1);
            importCount++;
            nameBytes += module.length + name.length;
            reaChargeLowerBound += 1024 + (module.length + name.length) * 6;
            if (imports.length < maxList) imports.push({ module: preview(module, 80), name: preview(name, 80), kind: KIND[k]! });
          }
          break;
        }
        case 7: {
          const n = r.leb();
          if (n > size) throw new WasmError(`export count ${n} impossible in ${size} bytes`, start);
          for (let i = 0; i < n; i++) {
            const name = r.name();
            const k = r.byte();
            r.leb();
            if (k > 4) throw new WasmError(`export kind ${k}`, r.pos - 1);
            exportCount++;
            nameBytes += name.length;
            reaChargeLowerBound += 1024 + name.length * 6;
            if (exportNames.has(name)) { if (dupExports.length < 10) dupExports.push(name); } else exportNames.add(name);
            if (exports.length < maxList) exports.push({ name: preview(name, 80), kind: KIND[k]! });
          }
          break;
        }
      }
      if (sections.length < MAX_SECTIONS) sections.push(sec);
      else sectionsNotListed++;
      pos = end;
    }
  } catch (e) {
    if (!(e instanceof WasmError)) throw e;
    parseError = e;
  }

  if (sectionsNotListed) limitations.push(`${sectionsNotListed} section(s) beyond the first ${MAX_SECTIONS} were parsed but not listed; custom-section facts cover listed sections only.`);
  let engineValid: boolean | null = null;
  if (!ctx.truncated) {
    try { engineValid = WebAssembly.validate(new Uint8Array(b)); } catch { engineValid = false; }
  }

  if (parseError) {
    findings.push(makeFinding({ rule: 'wasm-malformed', classification: 'analysis-limitation', title: 'Malformed WASM structure', observation: `${parseError.message} (byte ${parseError.offset}).`, interpretation: 'Sections after this point are unknown. Malformed input is not by itself evidence of BLA.', confidence: 'high', evidence: [byteRef(sha, lp, parseError.offset, Math.min(parseError.offset + 16, ctx.sizeBytes), 'parse failure point', 'format')] }));
    unknowns.push(`${lp}: sections after byte ${parseError.offset}.`);
  }
  if (structural.length) {
    findings.push(makeFinding({ rule: 'wasm-section-order', classification: 'analysis-limitation', title: 'Invalid section ordering', observation: `${structuralCount} ordering problem(s): ` + structural.map((s) => `${s.msg} @${s.offset}`).slice(0, 10).join('; '), interpretation: 'Spec-invalid module; engines reject it, but lenient tools may read different content.', confidence: 'high', evidence: structural.slice(0, 10).map((s) => byteRef(sha, lp, s.offset, s.offset + 1, s.msg, 'format')) }));
  }
  if (dupExports.length) {
    findings.push(makeFinding({ rule: 'wasm-duplicate-exports', classification: 'analysis-limitation', title: 'Duplicate export names', observation: `Duplicates: ${dupExports.map((n) => JSON.stringify(preview(n, 60))).join(', ')}.`, interpretation: 'Spec-invalid; tools may disagree on which export a name denotes.', confidence: 'high', evidence: sections.filter((s) => s.id === 7).slice(0, 10).map((s) => byteRef(sha, lp, s.start, s.end, 'export section', 'format')) }));
  }

  const customs = sections.filter((s) => s.id === 0);
  const customBytes = customs.reduce((a, s) => a + (s.end - s.start), 0);
  const nonToolchain = customs.filter((s) => !TOOLCHAIN_CUSTOM.test(s.customName ?? ''));
  if (nonToolchain.length) {
    findings.push(makeFinding({
      rule: 'wasm-custom-sections',
      classification: 'metadata-only',
      title: 'Non-toolchain custom sections',
      observation: `${nonToolchain.length} custom section(s) with non-standard names (${nonToolchain.slice(0, 8).map((s) => JSON.stringify(preview(s.customName ?? '', 60))).join(', ')}); custom sections total ${customBytes} of ${ctx.sizeBytes} bytes.`,
      interpretation: 'Custom sections are never executed by the engine. Their content is metadata a host could read, but nothing here shows that any host does. Treat their text as untrusted.',
      confidence: 'high',
      evidence: nonToolchain.slice(0, 10).map((s) => byteRef(sha, lp, s.start, s.end, `custom "${preview(s.customName ?? '', 60)}"`, 'format')),
      metrics: { customSections: customs.length, nonToolchain: nonToolchain.length, customBytes },
    }));
  }
  const markers: ReturnType<typeof scanSegments>['blaMarkers'] = [];
  let scanned = 0;
  for (const s of customs) {
    if (ctx.budget.timedOut()) { limitations.push('Custom-section text scan stopped: time budget exhausted.'); break; }
    const n = Math.min(s.end - s.start, ctx.budget.limits.maxScanBytes - scanned);
    if (n <= 0) { limitations.push('Custom-section text scan stopped at the scan budget.'); break; }
    const sc = scanSegments(asciiSegments(b.subarray(s.start, s.start + n), s.start), sha, lp, ctx.budget, `custom section "${preview(s.customName ?? '', 40)}"`);
    findings.push(...sc.findings);
    markers.push(...sc.blaMarkers);
    scanned += n;
  }
  for (const s of customs) {
    const nm = s.customName ?? '';
    if (/\bbla\./.test(nm)) markers.push({ marker: nm.slice(0, 80), ref: byteRef(sha, lp, s.start, s.end, 'custom section name', 'format') });
  }
  const mf = markerFinding(markers);
  if (mf) findings.push(mf);

  const reaLimit = limit('wasm.interfaceRepresentationBytes');
  if (reaChargeLowerBound > reaLimit / 2) {
    const exceeds = reaChargeLowerBound > reaLimit;
    const exportSec = sections.filter((s) => s.id === 7 || s.id === 2).slice(0, 10);
    findings.push(makeFinding({
      rule: 'wasm-interface-representation',
      classification: 'resource-limit',
      title: exceeds ? 'Import/export interface exceeds REA representation budget' : 'Import/export interface approaches REA representation budget',
      observation: `${importCount} imports + ${exportCount} exports, ${nameBytes} name bytes; lower-bound REA charge ${reaChargeLowerBound} bytes (1024 + 6*name bytes per entry, WAT text and signature terms omitted).`,
      interpretation: `REA bounds typed interface decoding at ${reaLimit} bytes (${limitSource('wasm.interfaceRepresentationBytes')}). ${exceeds ? 'Even the lower bound exceeds it: expect a capacity refusal from inspect_wasm_artifact.' : 'The true charge is higher than this lower bound and may exceed it.'}`,
      confidence: exceeds ? 'high' : 'medium',
      evidence: exportSec.map((s) => byteRef(sha, lp, s.start, s.end, `${s.name} section`, 'format')),
      metrics: { imports: importCount, exports: exportCount, nameBytes, reaChargeLowerBound, reaLimit },
    }));
    actions.push({
      kind: 'manual-review',
      title: 'Use this bounded export/import inventory instead of repeating whole-interface decoding',
      rationale: 'REA has no documented setting for the WASM interface representation budget in 6.8.0; repeating the call will fail the same way.',
      prerequisites: ['Confirm REA actually returned a resource_constraint for this module.'],
      risk: 'read-only',
      expectedBenefit: 'Names/kinds/counts are available with byte provenance; signatures remain unknown.',
      exitCriterion: 'Stop if the question needs function bodies or signatures beyond the budget; report them as unknown.',
    });
  }
  if (exportCount > 0 && funcCount > 0 && exportCount > funcCount * 4 && exportCount > 64) {
    findings.push(makeFinding({ rule: 'wasm-export-inflation', classification: 'possible-decoy', title: 'Many more exports than defined functions', observation: `${exportCount} exports for ${funcCount} defined functions.`, interpretation: 'Many names aliasing few functions inflate the interface; an export name says nothing about whether JS calls it.', confidence: 'medium', evidence: sections.filter((s) => s.id === 7).slice(0, 10).map((s) => byteRef(sha, lp, s.start, s.end, 'export section', 'format')), metrics: { exports: exportCount, functions: funcCount } }));
  }
  if (engineValid === false && !parseError && structural.length === 0) {
    limitations.push('The V8 engine rejected the module although the section framing parsed; body-level validity issues exist.');
  }

  const status = parseError || structural.length || ctx.truncated ? 'partial' : 'complete';
  return {
    status,
    format: 'wasm',
    formatConfidence: 'high',
    findings,
    limitations,
    unknowns,
    suggestedActions: actions,
    facts: {
      version,
      engineValid,
      sections: sections.map((s) => ({ id: s.id, name: s.name, start: s.start, end: s.end, ...(s.customName !== undefined ? { customName: preview(s.customName, 80) } : {}) })).slice(0, maxList),
      types: typeCount,
      functions: funcCount,
      bodies: codeCount,
      importCount,
      exportCount,
      imports,
      exports,
      listsTruncated: importCount > maxList || exportCount > maxList,
      customBytes,
    },
  };
}

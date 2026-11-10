// Electron ASAR: Chromium Pickle framing + JSON index. Header-only inventory; members are never extracted.
// Layout: u32 4 | u32 headerBytes | u32 payloadBytes(=headerBytes-4) | u32 jsonBytes | JSON | pad | data
import { makeFinding, preview } from '../core/findings.js';
import { readRange, sha256Bytes } from '../core/files.js';
import { findDuplicateKeys } from '../core/json-dupes.js';
import { byteRef } from '../core/provenance.js';
import type { AnalyzeContext, AnalyzerResult, Finding, SuggestedAction } from '../core/types.js';
import { CATALOG_UPSTREAM, limit, limitSource } from '../rea/failure-catalog.js';
import { asciiSegments, markerFinding, scanSegments } from './generic.js';

export interface AsarMember {
  path: string;
  offset: number | null;
  size: number;
  unpacked: boolean;
  integrityHash: string | null;
  link: string | null;
}

const MAX_INDEX_DEPTH = 256;

function unsafeName(n: string): boolean {
  return n === '' || n === '.' || n === '..' || /[\\/\u0000]/.test(n);
}

function linkEscapes(memberPath: string, target: string): boolean {
  if (target.startsWith('/') || /^[A-Za-z]:/.test(target) || target.includes('\0')) return true;
  const parts = memberPath.split('/').slice(0, -1);
  for (const seg of target.split(/[\\/]/)) {
    if (seg === '..') { if (parts.length === 0) return true; parts.pop(); }
    else if (seg !== '.' && seg !== '') parts.push(seg);
  }
  return false;
}

export async function analyzeAsar(ctx: AnalyzeContext): Promise<AnalyzerResult & { selectedMember?: { logicalPath: string; bytes: Buffer } }> {
  const sha = ctx.sha256;
  const lp = ctx.logicalPath;
  const findings: Finding[] = [];
  const limitations: string[] = ['Header/index inventory only; member contents are not extracted or analyzed unless selected with --member.'];
  const unknowns: string[] = [];
  const actions: SuggestedAction[] = [];
  const prefix = ctx.bytes.length >= 16 ? ctx.bytes.subarray(0, 16) : await readRange(ctx.path, 0, 16);
  const fail = (title: string, observation: string, end = Math.min(16, ctx.sizeBytes)): AnalyzerResult => {
    findings.push(makeFinding({ rule: 'asar-invalid-header', classification: 'analysis-limitation', title, observation, interpretation: 'The archive index cannot be trusted or parsed. Malformed framing is not by itself evidence of BLA.', confidence: 'high', evidence: [byteRef(sha, lp, 0, end, 'Pickle prefix', 'format')] }));
    unknowns.push(`${lp}: archive inventory (header invalid).`);
    return { status: 'failed', format: 'asar', formatConfidence: 'medium', findings, limitations, unknowns, facts: {} };
  };
  if (prefix.length < 16) return fail('Truncated ASAR prefix', `Only ${prefix.length} bytes; 16 are required.`);
  const headerBytes = prefix.readUInt32LE(4);
  const payloadBytes = prefix.readUInt32LE(8);
  const jsonBytes = prefix.readUInt32LE(12);
  // Same extent rules as REA's AsarHeader.ts.
  if (prefix.readUInt32LE(0) !== 4 || headerBytes < 8 || payloadBytes !== headerBytes - 4 || jsonBytes > payloadBytes - 4) {
    return fail('Invalid ASAR Pickle extents', `size-pickle=${prefix.readUInt32LE(0)}, headerBytes=${headerBytes}, payloadBytes=${payloadBytes}, jsonBytes=${jsonBytes}.`);
  }
  if (headerBytes > ctx.sizeBytes - 8) return fail('ASAR header exceeds file', `headerBytes=${headerBytes} but file has ${ctx.sizeBytes} bytes.`);
  const dataStart = 8 + headerBytes;
  const dataBytes = ctx.sizeBytes - dataStart;
  const facts: Record<string, unknown> = { headerBytes, jsonBytes, dataStart, dataBytes, archiveBytes: ctx.sizeBytes };

  const reaDefault = limit('asar.defaultMaxHeaderBytes');
  const reaMax = limit('asar.maximumMaxHeaderBytes');
  if (headerBytes > reaDefault) {
    const within = headerBytes <= reaMax;
    findings.push(makeFinding({
      rule: 'asar-header-exceeds-rea-default',
      classification: 'resource-limit',
      title: 'ASAR header larger than REA default admission',
      observation: `Header/index is ${headerBytes} bytes (JSON ${jsonBytes} bytes) against a data region of ${dataBytes} bytes.`,
      interpretation: `REA's default asar.max_header_bytes is ${reaDefault} (${limitSource('asar.defaultMaxHeaderBytes')}), settable up to ${reaMax}. With defaults REA is expected to refuse admission. Large indexes also occur in legitimate apps; an index far larger than its payload is a BLA-style inflation pattern, not proof.`,
      confidence: 'high',
      evidence: [byteRef(sha, lp, 4, 8, 'u32 headerBytes', 'format'), byteRef(sha, lp, 16, 16 + jsonBytes, 'JSON index', 'format')],
      limitations: [`The connected REA may use a different default; its own details.limit is authoritative.`],
      metrics: { headerBytes, reaDefault, reaMaximum: reaMax, headerToDataRatio: dataBytes > 0 ? Number((headerBytes / dataBytes).toFixed(3)) : -1 },
    }));
    actions.push(within ? {
      kind: 'rea-tool',
      title: `If REA reports ASAR admission for ${lp}, raise asar.max_header_bytes to ${headerBytes} and retry once`,
      rationale: 'Supported runtime setting; source_paths cannot bypass header admission.',
      operation: 'update_analysis_settings',
      parametersHint: { changes: [{ setting: 'asar.max_header_bytes', action: 'set', value: headerBytes }] },
      prerequisites: [
        'REA actually returned an admission error whose details.limit names asar.max_header_bytes.',
        'tools/list advertises update_analysis_settings with this setting; bounds in details.limit are authoritative.',
        `Host memory and the user's resource policy allow a ${(headerBytes / 1048576).toFixed(1)} MiB index.`,
      ],
      risk: 'changes-settings',
      documentation: [`https://github.com/morluto/rea/blob/${CATALOG_UPSTREAM.commit}/docs/design/limits-and-recovery.md`],
      expectedBenefit: 'Full-archive inventory and JavaScript application analysis can proceed (hypothesis; payload limits may still apply).',
      exitCriterion: 'Stop if the same admission error repeats after the change, or the setting is not advertised.',
    } : {
      kind: 'stop',
      title: `ASAR header exceeds REA's documented maximum setting (${reaMax})`,
      rationale: 'No supported setting admits this header; do not patch REA or the archive.',
      prerequisites: [],
      risk: 'read-only',
      exitCriterion: 'Report the archive index as unavailable to REA; use Anti-BLA header inventory as partial evidence.',
    });
  }

  if (jsonBytes > ctx.budget.limits.maxHeaderBytes || ctx.budget.readAllowance(jsonBytes) < jsonBytes) {
    limitations.push(`JSON index (${jsonBytes} bytes) not parsed: exceeds Anti-BLA header/read budget.`);
    unknowns.push(`${lp}: member inventory (index not parsed within budget).`);
    ctx.budget.markTruncated('ASAR index exceeded header budget');
    return { status: 'partial', format: 'asar', formatConfidence: 'high', findings, limitations, unknowns, facts, suggestedActions: actions };
  }
  const inPrefix = jsonBytes + 16 <= ctx.bytes.length;
  const jsonBuf = inPrefix ? ctx.bytes.subarray(16, 16 + jsonBytes) : await readRange(ctx.path, 16, jsonBytes);
  if (!inPrefix) ctx.budget.chargeRead(jsonBuf.length);
  const jsonText = jsonBuf.toString('utf8');
  let root: unknown;
  try {
    root = JSON.parse(jsonText);
  } catch (e) {
    findings.push(makeFinding({ rule: 'asar-index-unparseable', classification: 'analysis-limitation', title: 'ASAR JSON index cannot be parsed', observation: preview((e as Error).message, 200), interpretation: 'Inventory unavailable. A RangeError usually means hostile nesting depth.', confidence: 'high', evidence: [byteRef(sha, lp, 16, 16 + jsonBytes, 'JSON index', 'format')] }));
    unknowns.push(`${lp}: member inventory.`);
    return { status: 'partial', format: 'asar', formatConfidence: 'high', findings, limitations, unknowns, facts, suggestedActions: actions };
  }
  const dups = findDuplicateKeys(jsonText);
  if (dups.length) {
    findings.push(makeFinding({ rule: 'asar-duplicate-keys', classification: 'possible-poisoning', title: 'Duplicate member names in ASAR index', observation: `${dups.length} duplicate key(s), e.g. ${dups.slice(0, 3).map((d) => JSON.stringify(preview(d.key, 60)) + ' under ' + d.pointer).join('; ')}.`, interpretation: 'Different readers may resolve duplicates differently, so tools can disagree on what the archive contains.', confidence: 'high', evidence: dups.slice(0, 10).map((d) => byteRef(sha, lp, 16 + Buffer.byteLength(jsonText.slice(0, d.offset)), 16 + Buffer.byteLength(jsonText.slice(0, d.offset)) + d.key.length + 2, 'duplicate key', 'format')) }));
  }

  // Iterative walk of the index.
  const members: AsarMember[] = [];
  const unsafe: string[] = [];
  const outOfBounds: string[] = [];
  const badEntries: string[] = [];
  let dirs = 0;
  let nodeCap = false;
  const stack: { node: unknown; path: string; depth: number }[] = [{ node: root, path: '', depth: 0 }];
  let maxDepth = 0;
  let depthCapped = false;
  while (stack.length) {
    const { node, path, depth } = stack.pop()!;
    if (members.length + dirs > ctx.budget.limits.maxAstNodes) { nodeCap = true; break; }
    // Path strings grow with depth; cap nesting so hostile indexes cannot cost O(depth^2) memory.
    if (depth > MAX_INDEX_DEPTH) { depthCapped = true; continue; }
    if (depth > maxDepth) maxDepth = depth;
    if (!node || typeof node !== 'object') { badEntries.push(path || '/'); continue; }
    const n = node as Record<string, unknown>;
    if (n.files !== undefined) {
      if (!n.files || typeof n.files !== 'object' || Array.isArray(n.files)) { badEntries.push(path || '/'); continue; }
      dirs++;
      const names = Object.keys(n.files).sort();
      for (let i = names.length - 1; i >= 0; i--) {
        const name = names[i]!;
        const child = path ? `${path}/${name}` : name;
        if (unsafeName(name)) unsafe.push(child);
        stack.push({ node: (n.files as Record<string, unknown>)[name], path: child, depth: depth + 1 });
      }
      continue;
    }
    if (typeof n.link === 'string') {
      if (linkEscapes(path, n.link)) unsafe.push(`${path} -> ${n.link}`);
      members.push({ path, offset: null, size: 0, unpacked: false, integrityHash: null, link: n.link });
      continue;
    }
    const size = typeof n.size === 'number' ? n.size : NaN;
    const unpacked = n.unpacked === true;
    const integ = n.integrity as { hash?: unknown } | undefined;
    const integrityHash = integ && typeof integ.hash === 'string' ? integ.hash.toLowerCase() : null;
    if (!Number.isSafeInteger(size) || size < 0) { badEntries.push(path); continue; }
    if (unpacked) { members.push({ path, offset: null, size, unpacked, integrityHash, link: null }); continue; }
    const offStr = typeof n.offset === 'string' ? n.offset : typeof n.offset === 'number' ? String(n.offset) : '';
    if (!/^\d{1,16}$/.test(offStr)) { badEntries.push(path); continue; }
    const offset = Number(offStr);
    if (!Number.isSafeInteger(offset) || offset + size > dataBytes) outOfBounds.push(path);
    members.push({ path, offset, size, unpacked, integrityHash, link: null });
  }
  if (depthCapped) { limitations.push(`Index entries nested deeper than ${MAX_INDEX_DEPTH} levels were not walked.`); unknowns.push(`${lp}: entries below index depth ${MAX_INDEX_DEPTH}.`); }
  if (nodeCap) { limitations.push(`Index walk stopped at ${ctx.budget.limits.maxAstNodes} entries.`); unknowns.push(`${lp}: entries beyond the walk cap.`); }

  const idxRef = byteRef(sha, lp, 16, 16 + jsonBytes, 'JSON index', 'format');
  if (unsafe.length) {
    findings.push(makeFinding({ rule: 'asar-unsafe-member-path', classification: 'possible-poisoning', title: 'Member names or links that escape the archive root', observation: `${unsafe.length} unsafe name(s)/link(s), e.g. ${unsafe.slice(0, 5).map((u) => JSON.stringify(preview(u, 80))).join(', ')}.`, interpretation: 'Extracting such entries naively could write outside the destination (zip-slip). Anti-BLA never extracts; other tools may.', confidence: 'high', evidence: [idxRef], metrics: { unsafe: unsafe.length } }));
  }
  if (outOfBounds.length) {
    findings.push(makeFinding({ rule: 'asar-member-out-of-bounds', classification: 'analysis-limitation', title: 'Members whose byte ranges leave the archive', observation: `${outOfBounds.length} member(s) have offset+size beyond the ${dataBytes}-byte data region, e.g. ${outOfBounds.slice(0, 5).map((p) => JSON.stringify(preview(p, 80))).join(', ')}.`, interpretation: 'Truncated or crafted archive; those members cannot be read.', confidence: 'high', evidence: [idxRef], metrics: { outOfBounds: outOfBounds.length } }));
    unknowns.push(`${lp}: content of ${outOfBounds.length} out-of-bounds member(s).`);
  }
  if (badEntries.length) {
    findings.push(makeFinding({ rule: 'asar-malformed-entry', classification: 'analysis-limitation', title: 'Malformed index entries', observation: `${badEntries.length} entr(ies) with invalid size/offset/shape, e.g. ${badEntries.slice(0, 5).map((p) => JSON.stringify(preview(p, 80))).join(', ')}.`, interpretation: 'Entries cannot be located.', confidence: 'high', evidence: [idxRef] }));
  }
  const packed = members.filter((m) => m.offset !== null && Number.isSafeInteger(m.offset) && m.size > 0).sort((a, b) => a.offset! - b.offset! || a.size - b.size);
  let overlaps = 0;
  let covered = 0;
  for (let i = 0, end = -1; i < packed.length; i++) {
    const m = packed[i]!;
    if (m.offset! < end) overlaps++;
    covered += Math.max(0, m.offset! + m.size - Math.max(end, m.offset!));
    end = Math.max(end, m.offset! + m.size);
  }
  if (overlaps) {
    findings.push(makeFinding({ rule: 'asar-overlapping-members', classification: 'possible-decoy', title: 'Members share overlapping byte ranges', observation: `${overlaps} member(s) overlap an earlier member's range.`, interpretation: 'Several names alias the same bytes; inventories over-count real content.', confidence: 'high', evidence: [idxRef], metrics: { overlaps } }));
  }

  // Index text is also untrusted content (member names can carry instructions).
  const scan = scanSegments([{ text: jsonText, byteStart: 16 }], sha, lp, ctx.budget, 'ASAR index');
  findings.push(...scan.findings);
  const markers = [...scan.blaMarkers];

  const sorted = members.map((m) => m.path).sort();
  Object.assign(facts, {
    files: members.filter((m) => !m.link).length,
    directories: dirs,
    links: members.filter((m) => m.link).length,
    unpacked: members.filter((m) => m.unpacked).length,
    withIntegrity: members.filter((m) => m.integrityHash).length,
    maxIndexDepth: maxDepth,
    dataBytesCovered: covered,
    inventorySample: sorted.slice(0, ctx.budget.limits.maxListEntries).map((p) => preview(p, 160)),
    inventoryTruncated: sorted.length > ctx.budget.limits.maxListEntries,
  });
  if (members.some((m) => m.unpacked)) unknowns.push(`${lp}: unpacked members live outside the archive (.asar.unpacked) and were not read.`);

  let selectedMember: { logicalPath: string; bytes: Buffer } | undefined;
  if (ctx.member !== undefined) {
    const want = ctx.member.replace(/\\/g, '/').replace(/^\/+/, '');
    const m = members.find((x) => x.path === want);
    if (!m) {
      limitations.push(`Requested member ${JSON.stringify(preview(want, 120))} not present in index.`);
    } else if (m.link || m.unpacked || m.offset === null || outOfBounds.includes(m.path)) {
      limitations.push(`Requested member ${JSON.stringify(preview(want, 120))} is a link, unpacked, or out of bounds; not read.`);
    } else if (ctx.budget.readAllowance(m.size) < m.size) {
      limitations.push(`Requested member (${m.size} bytes) exceeds read budget; not read.`);
    } else {
      const bytes = await readRange(ctx.path, dataStart + m.offset, m.size);
      ctx.budget.chargeRead(bytes.length);
      const digest = sha256Bytes(bytes);
      facts.selectedMember = { path: m.path, offset: dataStart + m.offset, size: m.size, sha256: digest, declaredIntegrity: m.integrityHash };
      if (m.integrityHash && m.integrityHash !== digest) {
        findings.push(makeFinding({ rule: 'asar-member-integrity-mismatch', classification: 'integrity-dependency', title: 'Member bytes do not match declared integrity hash', observation: `sha256(member)=${digest}, index declares ${m.integrityHash}.`, interpretation: 'The index and payload disagree. Electron integrity enforcement (if enabled) would reject this member; analysis of it may not reflect what runs.', confidence: 'high', evidence: [byteRef(sha, lp, dataStart + m.offset, dataStart + m.offset + m.size, `member ${m.path}`)] }));
      }
      selectedMember = { logicalPath: `${lp}/${m.path}`, bytes };
    }
  }
  if (packed.length && ctx.budget.limits.maxScanBytes > 0 && !selectedMember) {
    // Bounded binary scan of the start of the data region for markers/instructions.
    const n = Math.min(dataBytes, ctx.budget.limits.maxScanBytes);
    const allowed = ctx.budget.readAllowance(n);
    if (allowed > 0) {
      const head = await readRange(ctx.path, dataStart, allowed);
      ctx.budget.chargeRead(head.length);
      const s2 = scanSegments(asciiSegments(head, dataStart), sha, lp, ctx.budget, 'first bytes of ASAR payload');
      findings.push(...s2.findings);
      markers.push(...s2.blaMarkers);
      if (dataBytes > allowed) limitations.push(`Payload text scan covered ${allowed} of ${dataBytes} data bytes.`);
    }
  }
  const mf = markerFinding(markers);
  if (mf) findings.push(mf);
  const status = nodeCap || depthCapped || dups.length ? 'partial' : 'complete';
  return { status, format: 'asar', formatConfidence: 'high', findings, limitations, unknowns, facts, suggestedActions: actions, ...(selectedMember ? { selectedMember } : {}) };
}

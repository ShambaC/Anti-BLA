// Validates skills/anti-bla: frontmatter, reference links, anti-bla commands, and that every
// backticked REA-looking operation name exists in the pinned REA 6.8.0 tool list.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SKILL = join(ROOT, 'skills', 'anti-bla');

export function checkSkill(skillDir = SKILL): string[] {
  const errs: string[] = [];
  const reaTools = new Set((JSON.parse(readFileSync(join(ROOT, 'src', 'data', 'rea-tools-6.8.0.json'), 'utf8')) as { tools: string[] }).tools);
  const commands = new Set(['triage', 'inspect', 'rea-evidence', 'report']);
  const skillMd = readFileSync(join(skillDir, 'SKILL.md'), 'utf8');

  const fm = /^---\n([\s\S]*?)\n---\n/.exec(skillMd.replace(/\r\n/g, '\n'));
  if (!fm) errs.push('SKILL.md: missing YAML frontmatter');
  else {
    const name = /^name:\s*(.+)$/m.exec(fm[1]!)?.[1]?.trim();
    const desc = /^description:\s*(.+)$/m.exec(fm[1]!)?.[1]?.trim();
    if (name !== 'anti-bla') errs.push(`SKILL.md: name must be anti-bla (got ${name})`);
    if (!desc || desc.length < 40 || desc.length > 1024) errs.push('SKILL.md: description must be 40..1024 chars');
    if (/reverse-engineer-anything/.test(name ?? '')) errs.push('SKILL.md: must not reuse the REA skill name');
  }
  if (skillMd.split('\n').length > 200) errs.push('SKILL.md: keep under 200 lines');

  const files = ['SKILL.md', ...readdirSync(join(skillDir, 'references')).map((f) => join('references', f))];
  for (const f of ['threat-model.md', 'rea-integration.md', 'budget-recovery.md', 'format-playbooks.md', 'evidence-validation.md', 'reporting.md']) {
    if (!files.includes(join('references', f))) errs.push(`missing references/${f}`);
    if (!skillMd.includes(`references/${f}`)) errs.push(`SKILL.md does not link references/${f}`);
  }
  for (const rel of files) {
    const text = readFileSync(join(skillDir, rel), 'utf8');
    for (const m of text.matchAll(/\]\(([^)#\s]+)(#[^)]*)?\)/g)) {
      const target = m[1]!;
      if (/^https?:/.test(target)) {
        if (/github\.com\/morluto\/rea\/blob\/main\//.test(target)) errs.push(`${rel}: unpinned REA link ${target} (pin a commit)`);
        continue;
      }
      if (!existsSync(resolve(join(skillDir, dirname(rel)), target))) errs.push(`${rel}: broken link ${target}`);
    }
    for (const m of text.matchAll(/anti-bla ([a-z-]+)/g)) {
      const c = m[1]!;
      if (!commands.has(c) && !['cli', 'skill', 'report', 'json'].includes(c) && !c.startsWith('-')) errs.push(`${rel}: unknown anti-bla command "${c}"`);
    }
    for (const m of text.matchAll(/`([a-z]+(?:_[a-z0-9]+)+)`/g)) {
      const op = m[1]!;
      // Only names shaped like REA operations; field names (source_paths, parent_evidence_id...) are allowed.
      if (/^(analyze|inspect|update|export|import|close|open|trace|compare|record|list|search|extract|recover|observe|verify|capture|find|build|correlate|reconcile|get|set|decompile|procedure|start|stop)_/.test(op) && !reaTools.has(op)) {
        errs.push(`${rel}: \`${op}\` is not an advertised REA 6.8.0 tool`);
      }
    }
  }
  return errs;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const errs = checkSkill();
  if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
  console.log('skills/anti-bla: OK');
}

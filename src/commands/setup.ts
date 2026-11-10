// `anti-bla setup`: copies skills/anti-bla into agent skill directories (same locations REA's setup uses:
// Claude Code -> ~/.claude/skills, Codex/Cursor/Gemini CLI and other Agent Skills clients -> ~/.agents/skills).
// Opt-in: prints the plan, writes only with --yes or an interactive "y". Never touches REA files or MCP config.
import { cp, mkdir, readdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { UsageError } from './assemble.js';

export const SKILL_SOURCE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'skills', 'anti-bla');
export const CLIENTS = ['claude', 'agents'] as const;
export type Client = (typeof CLIENTS)[number];

export interface SetupOptions {
  clients?: Client[];
  project?: string;
  dryRun?: boolean;
  yes?: boolean;
  uninstall?: boolean;
  home?: string;
  source?: string;
  log?: (line: string) => void;
}

export interface PlanItem {
  client: Client;
  destination: string;
  action: 'install' | 'update' | 'unchanged' | 'remove' | 'absent';
  backup?: string;
}

function destinations(o: SetupOptions): { client: Client; destination: string }[] {
  const home = o.home ?? homedir();
  const claudeRoot = o.project ? join(resolve(o.project), '.claude') : process.env.CLAUDE_CONFIG_DIR || join(home, '.claude');
  const agentsRoot = o.project ? join(resolve(o.project), '.agents') : join(home, '.agents');
  const wanted = o.clients ?? (o.project || existsSync(claudeRoot) ? ['claude', 'agents'] : ['agents']);
  return wanted.map((client) => ({ client, destination: join(client === 'claude' ? claudeRoot : agentsRoot, 'skills', 'anti-bla') }));
}

async function files(dir: string): Promise<Map<string, Buffer>> {
  const out = new Map<string, Buffer>();
  const walk = async (d: string) => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile()) out.set(relative(dir, p).split('\\').join('/'), await readFile(p));
    }
  };
  await walk(dir);
  return out;
}

async function sameTree(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([files(a), files(b)]);
  if (x.size !== y.size) return false;
  for (const [k, v] of x) if (!y.get(k)?.equals(v)) return false;
  return true;
}

async function isOurSkill(dir: string): Promise<boolean> {
  try { return /^name:\s*anti-bla\s*$/m.test(await readFile(join(dir, 'SKILL.md'), 'utf8')); } catch { return false; }
}

export async function planSetup(o: SetupOptions): Promise<PlanItem[]> {
  const source = o.source ?? SKILL_SOURCE;
  if (!o.uninstall && !existsSync(join(source, 'SKILL.md'))) throw new UsageError(`Skill source not found: ${source}`);
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const plan: PlanItem[] = [];
  for (const { client, destination } of destinations(o)) {
    const exists = existsSync(destination);
    if (o.uninstall) {
      plan.push({ client, destination, action: exists && (await isOurSkill(destination)) ? 'remove' : 'absent' });
    } else if (!exists) plan.push({ client, destination, action: 'install' });
    else if (await sameTree(source, destination)) plan.push({ client, destination, action: 'unchanged' });
    else plan.push({ client, destination, action: 'update', backup: `${destination}.backup-${stamp}` });
  }
  return plan;
}

export async function runSetup(o: SetupOptions): Promise<PlanItem[]> {
  const log = o.log ?? ((l: string) => process.stdout.write(l + '\n'));
  const plan = await planSetup(o);
  log(o.uninstall ? 'anti-bla setup --uninstall plan:' : 'anti-bla setup plan (REA files and MCP config are never touched):');
  for (const p of plan) log(`  [${p.client}] ${p.action.padEnd(9)} ${p.destination}${p.backup ? `  (existing copy backed up to ${p.backup})` : ''}`);
  const work = plan.filter((p) => p.action === 'install' || p.action === 'update' || p.action === 'remove');
  if (work.length === 0) { log('Nothing to do.'); return plan; }
  if (o.dryRun) { log('Dry run: nothing written.'); return plan; }
  let go = !!o.yes;
  if (!go && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    go = /^y(es)?$/i.test((await rl.question('Apply these changes? [y/N] ')).trim());
    rl.close();
  }
  if (!go) { log('Not applied. Re-run with --yes to apply (or --dry-run to only preview).'); return plan; }
  const source = o.source ?? SKILL_SOURCE;
  for (const p of work) {
    if (p.action === 'remove') { await rm(p.destination, { recursive: true, force: true }); continue; }
    if (p.backup) await rename(p.destination, p.backup);
    await mkdir(dirname(p.destination), { recursive: true });
    await cp(source, p.destination, { recursive: true, errorOnExist: true, force: false });
    if (!(await stat(join(p.destination, 'SKILL.md'))).isFile()) throw new Error(`copy failed: ${p.destination}`);
  }
  log(o.uninstall ? 'Removed. Restart your agent.' : 'Installed. Restart your agent so it discovers the skill.');
  if (!o.uninstall) log('CLI: `npm install -g anti-bla` puts `anti-bla` on PATH, or the skill falls back to `npx -y anti-bla`. REA itself: `npx rea-agents setup`.');
  return plan;
}

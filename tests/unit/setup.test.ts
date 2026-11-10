import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runSetup } from '../../src/commands/setup.js';
import { withTemp } from '../helpers.js';

const quiet = { log: () => {} };

test('setup: dry run writes nothing; --yes installs both clients; rerun is unchanged; edits are backed up; uninstall removes only ours', async () => {
  await withTemp(async (d) => {
    const plan0 = await runSetup({ project: d, dryRun: true, ...quiet });
    assert.deepEqual(plan0.map((p) => p.action), ['install', 'install']);
    assert.equal(existsSync(join(d, '.claude')), false);

    await runSetup({ project: d, yes: true, ...quiet });
    const claude = join(d, '.claude', 'skills', 'anti-bla');
    const agents = join(d, '.agents', 'skills', 'anti-bla');
    assert.ok(existsSync(join(claude, 'SKILL.md')) && existsSync(join(agents, 'references', 'budget-recovery.md')));

    assert.deepEqual((await runSetup({ project: d, yes: true, ...quiet })).map((p) => p.action), ['unchanged', 'unchanged']);

    writeFileSync(join(claude, 'SKILL.md'), '---\nname: anti-bla\n---\nlocal edit\n');
    const upd = await runSetup({ project: d, yes: true, clients: ['claude'], ...quiet });
    assert.equal(upd[0]!.action, 'update');
    assert.ok(readdirSync(join(d, '.claude', 'skills')).some((n) => n.startsWith('anti-bla.backup-')));

    // A foreign skill that happens to sit at the path is never removed.
    writeFileSync(join(agents, 'SKILL.md'), '---\nname: something-else\n---\n');
    const un = await runSetup({ project: d, yes: true, uninstall: true, ...quiet });
    assert.deepEqual(un.map((p) => p.action), ['remove', 'absent']);
    assert.equal(existsSync(claude), false);
    assert.equal(existsSync(agents), true);
  });
});

test('setup without --yes in a non-interactive shell changes nothing', async () => {
  await withTemp(async (d) => {
    await runSetup({ project: d, ...quiet });
    assert.equal(existsSync(join(d, '.claude')), false);
  });
});

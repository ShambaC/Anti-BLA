import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkSkill } from '../../scripts/check-skill.js';
import { ROOT, withTemp } from '../helpers.js';

const SKILL = join(ROOT, 'skills', 'anti-bla');

test('shipped skill passes validation', () => {
  assert.deepEqual(checkSkill(SKILL), []);
});

test('checker rejects invented REA operations, broken links and wrong names', async () => {
  await withTemp(async (d) => {
    cpSync(SKILL, d, { recursive: true });
    const p = join(d, 'SKILL.md');
    const s = readFileSync(p, 'utf8').replace('name: anti-bla', 'name: other')
      + '\nUse `inspect_wasm_skip_decoys` then [x](references/missing.md) and https://github.com/morluto/rea/blob/main/x.md [y](https://github.com/morluto/rea/blob/main/x.md)\n';
    writeFileSync(p, s);
    const errs = checkSkill(d).join('\n');
    assert.match(errs, /name must be anti-bla/);
    assert.match(errs, /inspect_wasm_skip_decoys/);
    assert.match(errs, /broken link references\/missing\.md/);
    assert.match(errs, /unpinned REA link/);
  });
});

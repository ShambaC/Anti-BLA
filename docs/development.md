# Development

Requires Node.js >= 22.13 (`node:sqlite`). No shell scripts are used; all tooling is `npm run` plus Node.

## Commands (`package.json` scripts)

- `npm run build`: `tsc -p tsconfig.json`; output goes to `dist/` (`dist/src/cli.js` is the `anti-bla` bin).
- `npm run typecheck`: `tsc --noEmit`.
- `npm test`: build, then `node --test` over `dist/tests/**/*.test.js`.
- `npm run test:unit`: build, then `dist/tests/unit/**`.
- `npm run test:integration`: build, then `dist/tests/integration/**` and `dist/tests/regression/**`.
- `npm run fixtures`: build, then `node dist/scripts/generate-fixtures.js`.
- `npm run check:skill`, `npm run bench`, `npm run bench:validate`: defined in `package.json`, but their targets (`scripts/check-skill.ts`, `benchmarks/runner.ts`, `benchmarks/validate-results.ts`) do not exist in the repository at the time of writing.

Run the CLI from a build: `node dist/src/cli.js --help` (and `<command> --help`).

## Fixtures

`npm run fixtures` rewrites `tests/fixtures/**` and `tests/fixtures/expected/hashes.json` (SHA-256 of every fixture). Layout: `clean/`, `bla-like/`, `malformed/`, `rea/` (REA captures, not generated).

- All fixtures are built by `scripts/generate-fixtures.ts` from scratch (WASM and ASAR byte builders, JS text, SQLite via `node:sqlite`). Nothing is derived from BLA source or output.
- SQLite fixture bytes depend on the Node SQLite version. Regenerate only deliberately, review the diff in `hashes.json`, and expect tests that pin hashes to need an update.
- Oversized cases (ASAR index above 16 MiB, WASM interface charge above 32 MiB) are not committed; they are built on demand in temp directories.
- `.gitattributes` sets `* text=auto eol=lf`, `tests/fixtures/** -text`, and marks `*.wasm`, `*.asar`, `*.sqlite`, `*.bin` as binary, so fixtures stay byte-exact on every OS. Do not re-encode or normalize line endings in fixture files.
- `@electron/asar` is used in tests only, as an independent ASAR reader to cross-check inventories.

## Adding a finding rule

1. Pick the format module (`src/formats/*.ts`) or the generic rule table (`RULES` in `src/formats/generic.ts`, which takes `id`, `classification`, `confidence`, `patterns`, `interpretation`, `nextSteps`).
2. Create findings only with `makeFinding` (`src/core/findings.ts`). It throws if `evidence` is empty, so every finding must cite bytes, AST position, format location, or a REA JSON pointer (`byteRef`, `textRef` in `src/core/provenance.ts`).
3. Write `observation` as a measurement and `interpretation` as a hedge. Set `confidence` honestly (low for heuristics). Quote target text only through `preview()` so it is bounded, control-free and redacted.
4. Never derive a `SuggestedAction` from target text.
5. If the rule corresponds to a documented BLA mechanism, decide whether it belongs in `MECHANISM_RULES` (`src/core/classification.ts`); that set drives `bla-like-mechanisms`.
6. Add a fixture (generator plus regenerated hashes) with an expectation in `tests/`, add a negative case from `clean/`, and update `docs/tool-contracts.md` (rule table) and `docs/limitation-matrix.md`.

## Updating the REA failure catalog

`src/data/rea-failure-patterns.json` pins REA limits and failure patterns from a specific upstream commit.

1. Read the REA source at the new version; copy values and source paths into `limits`.
2. Bump `catalogVersion`, and update `upstream.upstream_version`, `upstream.commit` and `upstream.verified_at`.
3. Patterns match structured fields first (`code`, `operation`, `detailsLimitSetting`, `detailsResource`, `hasPartialObservation`, `resourceLimitValues`; all specified fields must match). `alsoMatchText` is a list of exact substrings checked second (`src/rea/recommend-next-step.ts`). Never use fuzzy or regex matching on REA text.
4. Re-run the tests and, when possible, re-check the findings against a real REA run; record which predictions were confirmed in `docs/limitation-matrix.md`.
5. A connected REA's own diagnostics (`details.limit`, `inspect_analysis_settings`) always override the catalog.

## Platform notes

- Windows, Linux and macOS: paths in reports use `/` logical paths (`relative` then `sep` replaced). Absolute `path` values are native.
- Inode-based alias detection uses `dev:ino`; entries with inode 0 (some Windows filesystems) are not de-duplicated.
- `--output` writes a temp file next to the destination and renames it; keep the destination on a writable local filesystem.
- Do not add shell scripts; use Node scripts under `scripts/`.

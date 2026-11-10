# Threat model

## Assets

- The analyst's host: filesystem, network, credentials, processes.
- The integrity of the analyzed artifact (it must not be modified).
- The integrity of the analysis output: the report and the agent that reads it.
- The analyst's time and memory (resource exhaustion).

## Adversary

The artifact and everything derived from it is hostile. Specifically:

- Prompt injection in source text, comments, strings, ASAR member names, WASM custom sections, SQLite schema SQL, and REA output that embeds target strings.
- Parser bombs: deeply nested JS or JSON, huge ASAR indexes, huge WASM name tables, enormous generated files.
- Lying length fields: ASAR pickle sizes, member offsets and sizes, WASM LEB128 counts and section lengths, SQLite header page counts.
- Zip-slip style names and links in ASAR members.
- Duplicate JSON keys (ASAR index, REA JSON) so different parsers see different content.
- Honey source maps: `sourcesContent` that does not match the bundle, out-of-range source indices.
- Canary credentials intended to be tested, leaked or used.
- Contaminated REA Evidence JSON: tampered records, injected remediation text, paths pointing elsewhere.
- Symlinks and hard links that escape or double-count the scan root.
- Files that change during the scan.

Out of scope: an adversary who already controls the host, the Node.js binary, or `node_modules`.

## Controls implemented

Read-only access
- Every open of a target uses flag `'r'` (`src/core/files.ts`). No code path writes to a target.
- SHA-256 is streamed with a 1 MiB buffer (`sha256File`); memory does not grow with file size.
- Reads go through `readBounded`/`readRange`, which clamp to the real file length and the `Budget` allowance. Declared offsets past EOF read nothing.
- A post-analysis stat comparison downgrades results if the file changed (`changedSince`).

No execution of targets
- Targets are never executed, `eval`ed, `require`d, `import`ed, or loaded as modules. JS is parsed to an AST in a worker (`src/formats/js-worker.ts`); getters, `eval`/`Function`, and expressions are counted, never run.
- WASM is never instantiated. `WebAssembly.validate` is the only engine call (`src/formats/wasm.ts`); section parsing uses bounded LEB128 reads with no allocation driven by declared counts.
- ASAR archives are never extracted. Only the header/index is read; with `inspect --member`, one member is read into memory, hash-checked, and scanned in memory (`src/commands/inspect.ts`). It is never written to disk.

SQLite (`src/formats/sqlite.ts`)
- The target path is never opened by SQLite. The bytes already read (and budget-charged) are written to a private temp directory (`mkdtemp`, file created with `wx`) and removed afterward.
- Opened with `readOnly: true`, `allowExtension: false`, then `PRAGMA query_only = 1; PRAGMA trusted_schema = 0;`.
- Only fixed catalog queries run: `sqlite_master`, `pragma_function_list`, `pragma_table_xinfo(?)`. No `SELECT` on user tables, so generated columns, views and triggers are never evaluated.
- If the file exceeds the read budget the catalog is not opened.

Filesystem traversal (`walk`)
- Sorted, iterative traversal with depth and file-count caps.
- Symlinks are followed only when the real target stays inside the real root; others are excluded with a reason.
- Entries with the same `dev:ino` are reported once (hard-link and symlink dedupe). Non-regular files are skipped.

Resource bounds
- Time, bytes, file count, depth, finding count, AST nodes (`src/core/budgets.ts`).
- JS parse runs in a worker with a heap limit and timeout; the worker is replaced after a crash or timeout.
- ASAR header cap (`maxHeaderBytes`), scan window (`maxScanBytes`), per-rule hit cap (10,000) and cited-location cap (10).
- Duplicate-key detection is a single iterative pass (`src/core/json-dupes.ts`).

Output safety
- `--output` is written atomically (temp file with `wx`, then rename). It is refused if it equals an analyzed input or lies inside an analyzed directory, and refused if the file exists without `--force` (`writeOutput`).
- Previews of target text are single-line, bounded to `maxPreviewChars`, have control and bidi characters stripped, and are redacted for credential shapes (AWS keys, GitHub tokens, `sk-` keys, Slack tokens, JWTs, Bearer tokens, PEM private keys) (`src/core/findings.ts`).
- Markdown output escapes metacharacters and strips control characters (`src/reports/markdown.ts`); caveats are not truncated.
- `report` validates a stored report before rendering and caps its size.
- `--redact-paths` replaces absolute artifact paths in output.

Untrusted text handling
- Agent-directed text, tool names, endpoints, credentials and integrity strings are findings with confidence `low` or `medium`, quoted as data. Nothing in target content produces a `SuggestedAction`; actions come from fixed analyzer logic and the pinned catalog.
- `rea-evidence` never opens paths found in REA JSON. It scans REA JSON as contaminated input and keeps only `agent-directed-instruction` and `credential-shaped-string` hits from that scan.
- REA failure recognition uses structured fields first, then exact catalog substrings; no fuzzy matching.
- Attribution never reaches "confirmed" (`src/core/classification.ts`).

## Residual risks

- The TypeScript parser runs on hostile input inside a worker. A parser bug could crash the worker (handled) or, in the worst case, be exploitable within the Node process; worker isolation is a resource boundary, not a security sandbox.
- `WebAssembly.validate` runs V8's WASM validator on hostile bytes, on the main thread.
- `node:sqlite` parses a hostile database file (in a temp copy). A bug in SQLite's parser is possible. The temp copy exists briefly on disk in the OS temp directory.
- Regex scanning is bounded by `maxScanBytes` (4 MiB per file for generic/binary text; the whole budgeted prefix for JS/TS and source maps) and per-rule hit caps. Every quantifier is bounded (e.g. `s{1,5}`, `{16,2048}`) and regression tests feed known backtracking inputs, but the patterns are not formally proven ReDoS-free. The time budget is checked between rules and files, not inside a single match. `preview()` never redacts more than `4 x maxChars` characters.
- JS source text is scanned in full from the budgeted prefix, not limited to `maxScanBytes`.
- Rule detection is heuristic. Absence of a finding is not evidence of absence.
- A file can change between hashing and reading; detection is by stat stamp only, and mtime-preserving changes are missed.
- Temp-file names for `--output` are predictable (`<out>.anti-bla-<pid>.tmp`), created with `wx` so an existing file is not overwritten.
- Report consumers (agents, viewers) remain responsible for treating quoted target text as data.

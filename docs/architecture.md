# Architecture

Anti-BLA is a read-only, bounded CLI (`anti-bla triage|inspect|rea-evidence|report`) plus an agent skill. It complements REA (`rea-agents`): it reports artifact-side evidence of obstruction and recommends REA actions. It never calls REA itself.

## Data flow

Per artifact (`src/core/pipeline.ts`, `analyzePath`):

1. Fingerprint (`src/core/fingerprint.ts`): record a stat stamp (size, mtime, ino, dev), stream-hash the whole file with SHA-256, then read a budget-bounded prefix. If the time budget runs out while hashing, the file is excluded.
2. Detect (`src/formats/detect.ts`): magic bytes and structure first; extension only breaks ties. `inspect --format` overrides detection.
3. Analyze: dispatch by format to `javascript`/`typescript`, `source-map`, `asar`, `wasm`, `sqlite`, or the generic scanner. An analyzer exception becomes a `failed` result with an `analyzer-error` finding; it does not abort the batch.
4. Verify unchanged: re-stat the file. If the stamp changed, a `complete` result is downgraded to `partial` and a limitation is added.
5. Assemble (`src/commands/assemble.ts`): cap findings (`--max-findings`, lowest confidence dropped first), sort deterministically by logical path, byte offset, rule, id, de-duplicate suggested actions, compute `analysisStatus` and `attribution`, attach budget counters.

`triage` walks a directory first (`walk` in `src/core/files.ts`: sorted names, explicit stack, depth/file caps) and runs the pipeline per file. `inspect` runs it on one file and, with `--member`, analyzes one ASAR member in memory. `rea-evidence` parses REA JSON files instead of artifacts. `report` re-renders a stored report without reopening any target.

## Module map

- `src/cli.ts`: argument parsing, help, exit codes, error envelope.
- `src/commands/triage.ts`: directory walk, per-file pipeline, one worker host per run.
- `src/commands/inspect.ts`: single-file inspection, in-memory ASAR member analysis.
- `src/commands/rea-evidence.ts`: ingest REA Evidence/error JSON; never opens paths inside it.
- `src/commands/report.ts`: validate and re-render a stored report.
- `src/commands/assemble.ts`: report assembly, `UsageError`, atomic `writeOutput`.
- `src/core/types.ts`: report contract `anti-bla-report/v1`.
- `src/core/budgets.ts`: `Budget` class and default limits.
- `src/core/files.ts`: read-only file access, streaming hash, bounded reads, walker.
- `src/core/fingerprint.ts`: hash plus prefix read plus change detection.
- `src/core/pipeline.ts`: per-artifact dispatch.
- `src/core/classification.ts`: `aggregateStatus`, `attribution`.
- `src/core/findings.ts`: `makeFinding` (requires evidence), `redact`, `preview`, `capFindings`.
- `src/core/provenance.ts`: byte offset and line/column evidence references.
- `src/core/json-dupes.ts`: duplicate JSON key detection (bounded, iterative).
- `src/formats/detect.ts`: format detection.
- `src/formats/generic.ts`: regex rule scan (agent-directed text, credentials, endpoints, integrity strings, BLA markers), Electron fuse sentinel scan, fallback analyzer.
- `src/formats/javascript.ts`: JS/TS analyzer, `JsWorkerHost`, source map analysis.
- `src/formats/js-measure.ts`: AST measurements, run inside the worker.
- `src/formats/js-worker.ts`: worker entry point; parses only.
- `src/formats/asar.ts`: ASAR header/index inventory and checks.
- `src/formats/wasm.ts`: WASM section inventory, `WebAssembly.validate`, interface charge lower bound.
- `src/formats/sqlite.ts`: header facts and schema catalog from a private temp copy.
- `src/rea/evidence-schema.ts`, `src/rea/parse-evidence.ts`: REA Evidence/error shape handling.
- `src/rea/failure-catalog.ts`: loads `src/data/rea-failure-patterns.json` (pinned REA limits and failure patterns).
- `src/rea/recommend-next-step.ts`: matches catalog patterns, emits findings and conditional REA actions.
- `src/reports/json.ts`: JSON output and `validateReport`.
- `src/reports/markdown.ts`: Markdown rendering with escaping.
- `scripts/generate-fixtures.ts`: builds the owned fixture corpus.

## Worker-isolated JavaScript parse

`JsWorkerHost` (`src/formats/javascript.ts`) owns one reusable `worker_threads` Worker running `js-worker.js`. The worker is created with `resourceLimits` (`maxOldGenerationSizeMb` from `jsWorkerHeapMb`, default 512; `stackSizeMb: 8`). Each parse has a timeout (`min(jsParseTimeoutMs, remaining time budget)`). On timeout, worker error, or unexpected exit the worker is terminated and the next file gets a fresh one. The result is a `js-parse-incomplete` finding and `partial` status, not an abort. The worker uses TypeScript's `ts.createSourceFile` (in `js-measure.ts`) and never evaluates target code. AST walks stop at `maxAstNodes`.

## Budget manager

`Budget` (`src/core/budgets.ts`) is one object shared by every detector. Defaults: 2000 files, 32 MiB per file, 128 MiB total read, 30 s, depth 32, 500 findings, 2,000,000 AST nodes, 10 s JS parse timeout, 512 MB worker heap, 64 MiB ASAR header cap, 4 MiB scan window, 200 list entries, 120 preview characters. The first six are CLI flags (`--max-files`, `--max-file-bytes`, `--max-total-bytes`, `--max-time-ms`, `--max-depth`, `--max-findings`); values must be positive safe integers. `readAllowance` returns `min(fileSize, maxFileBytes, remaining total)`; `chargeRead` accounts every read. Any cut sets `truncated` with a reason, which forces `analysisStatus` to `partial` and appears in `limitations`. Hashing is streamed and counted separately (`bytesHashed`) so a file larger than the read cap still gets a full-file SHA-256.

## Why the CLI makes no REA calls

REA tools are an MCP surface whose live `tools/list` schema is the authority. A CLI that called REA would need credentials, a transport, and trust in REA output that can itself be contaminated by the target. Instead the CLI emits `SuggestedAction` records (`parametersHint` advisory) that the host agent validates against its connected REA before use. `rea-evidence` consumes REA output the host already holds, treats it as untrusted, and never opens paths named inside it. Pinned REA limits come from the catalog JSON, labeled with the upstream version and verification date.

## Dependencies

- Runtime: `typescript` only, used as a parser inside the worker (and by the fixture script).
- `node:sqlite` is built in (Node >= 22.13); no native add-on, no SQLite package.
- Dev: `@types/node`.
- Dev: `@electron/asar`, used only as an independent oracle in tests (Anti-BLA's ASAR code does not use it). Its transitive `glob`/`minimatch` dependencies carry moderate `npm audit` advisories; these are dev-only and not shipped (`package.json` `files` lists `dist/src`, `skills`, `docs`).

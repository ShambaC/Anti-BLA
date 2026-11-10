# Tool contracts

Source of truth: `src/core/types.ts`. Schema id: `anti-bla-report/v1`. All text fields that quote the target are untrusted data.

## Report fields (`AntiBlaReport`)

- `schemaVersion`: always `"anti-bla-report/v1"`.
- `command`: `"triage" | "inspect" | "rea-evidence"`.
- `analysisStatus`: overall status, see below.
- `analyzedAt`: ISO-8601 timestamp (with `budgets.elapsedMs`, the only run-dependent fields).
- `toolVersion`: Anti-BLA version string.
- `artifacts[]`: `{ path, logicalPath, sha256, sizeBytes, detectedFormat, formatConfidence, analysisStatus }`. `path` is absolute (or `<redacted>/<logicalPath>` with `--redact-paths`). `sha256` covers the whole file even when reads were truncated. `formatConfidence` is `low|medium|high`. For an ASAR member analyzed with `--member`, `path` is `<archive>#<member>`. Optional `facts` holds analyzer-specific measurements (for example ASAR `headerBytes`/`jsonBytes`/`inventorySample`, WASM `exports`/`imports`/`sections`, SQLite `tables`/`analyzerSqliteVersion`, JS node counts). Names inside `facts` come from the target and are previewed (bounded, redacted).
- `findings[]`: see below.
- `suggestedActions[]`: see below.
- `coverage`: `examined` (logical paths analyzed) and `excluded[]` (`{ path, reason }`: unreadable, symlink outside root, alias, depth/file cap, time budget).
- `limitations[]`: strings describing what the result does not establish, including budget cuts (`Budget: ...`).
- `unknowns[]`: strings naming what remains unknown (never-evaluated runtime values, unread members, etc.).
- `attribution`: `{ status, basis[] }`, see below.
- `rea` (only `rea-evidence`): `{ evidenceIds[], sourceVersion?, records[] }`. Each record keeps `inputPath`, `jsonPointer`, `shape` (`evidence|error|unknown`), evidence and parent ids, `operation`, `provider`, `subjectSha256`, `confidence`, `authority`, `limitations`, `unknowns`, `coveragePointers`, `resourceLimits`, and for errors `{ code, category, message, retryable, remediation, limit, partialObservation, evidenceReference, resource }`.
- `budgets`: `{ elapsedMs, bytesRead, bytesHashed, truncated, limits }`. `limits` echoes every effective cap. `truncated: true` makes `analysisStatus` `partial` at best.

### Finding

`{ id, rule, classification, title, observation, interpretation, confidence, evidence[], limitations[], nextSteps[], metrics? }`.

- `id`: `F-` plus 12 hex characters of a hash of rule, title and evidence anchors; stable across runs.
- `observation` states what was measured; `interpretation` states what it may mean. Neither claims runtime behavior.
- `confidence`: `low|medium|high`. It is confidence in the observation or prediction, not in BLA attribution.
- `classification`: `possible-poisoning`, `possible-decoy`, `resource-limit`, `metadata-only`, `reachability-unknown`, `integrity-dependency`, `runtime-discrepancy`, `analysis-limitation`. (`runtime-discrepancy` is in the type; no rule emits it.)
- `evidence[]` is never empty (`makeFinding` throws). Each `EvidenceRef`: `kind` (`bytes|ast|format|rea|derived`), optional `artifactSha256`, `logicalPath`, `byteStart`, `byteEnd`, `astLocation {line, column}` (1-based), `reaEvidenceId`, `jsonPointer`, `note`.
- `metrics`: flat map of numbers, strings, booleans.

### analysisStatus vs per-artifact status

Each artifact has `analysisStatus` in `complete|partial|failed|unsupported`:
- `complete`: the analyzer covered the whole file within budget.
- `partial`: covered a prefix, hit a budget, the parser recovered from errors, or only generic indicators exist for a native or unknown binary.
- `failed`: the analyzer could not parse the artifact (bad header, analyzer error).
- `unsupported`: no analyzer for the format; generic scan only.

The report-level `analysisStatus` (`aggregateStatus` in `src/core/classification.ts`):
- no artifacts: `failed` if anything was excluded, else `unsupported`;
- all artifacts `failed`: `failed`; all `unsupported`: `unsupported`;
- `complete` only when every artifact is `complete` and nothing was excluded or truncated;
- otherwise `partial`. One failed artifact among others gives `partial`, not `failed`.

### Attribution

`attribution.status` is `none-observed`, `bla-like-mechanisms` or `bla-markers-observed`. There is no `confirmed`: markers can be planted and mechanisms occur in legitimate software.
- `bla-markers-observed`: a `bla-marker-string` finding exists.
- `bla-like-mechanisms`: otherwise, either one non-low-confidence **structural** finding (`js-literal-alternative-explosion`, `js-primitive-byte-charge`, `js-getter-ring`, `js-alias-table`, `wasm-export-inflation`, `sqlite-generated-column-unknown-function`, `sourcemap-unreferenced-content`, `electron-fuse-sentinel-flood`, `agent-directed-instruction`), or at least two non-low-confidence **capacity** findings (`asar-header-exceeds-rea-default`, `wasm-interface-representation`, `js-expression-depth`, `sourcemap-bundle-mismatch`). A single large-but-legitimate input does not trigger it.
- `basis[]` lists `"<findingId> <rule>"` entries.

### SuggestedAction

`{ kind, title, rationale, operation?, parametersHint?, prerequisites[], risk, relatedEvidenceIds?, documentation?, expectedBenefit?, exitCriterion? }`.
- `kind`: `rea-tool | cli-command | manual-review | stop`.
- `risk`: `read-only | changes-settings | requires-approval`.
- `operation` names a REA tool. `parametersHint` is advisory only: the host must check the live REA `tools/list` schema before calling and satisfy every `prerequisites` item. Anti-BLA never executes an action.
- `expectedBenefit` is a hypothesis. `exitCriterion` says when to stop (for example, the same REA limit repeating).
- Actions come from analyzer logic and the pinned catalog, never from target text.

## Error envelope

With `--json`, a failure writes this to stdout:

```json
{"schemaVersion":"anti-bla-error/v1","error":{"code":"...","message":"..."}}
```

Codes: `invalid_input` (default usage error), `not_found`, `unsafe_output`, `output_exists`, `invalid_report`, `internal_error` (any non-usage exception). Without `--json` the message goes to stderr as `anti-bla: <message>`.

## Exit codes (`src/cli.ts`)

- `0`: report produced and `analysisStatus` is not `failed` (so `partial` and `unsupported` exit 0); `--help`, `--version`; `report` rendered.
- `1`: report produced and `analysisStatus` is `failed`.
- `2`: usage or input error, unknown command or option, missing file, unsafe or existing output, internal error.

## Output channels

`--json` prints the report to stdout. `--output <file>` writes the report atomically and prints `report written: <file>` to stderr; with both flags stdout stays empty. Without `--json`, stdout gets a short text summary. `report <file> [--format markdown|json]` re-renders a stored report.

## Finding rules

Confidence is the default in code; "a / b" means it depends on the case.

| Rule | Classification | Confidence |
|---|---|---|
| `agent-directed-instruction` | possible-poisoning | medium |
| `analyzer-tool-reference` | possible-poisoning | low |
| `credential-shaped-string` | possible-poisoning | low |
| `unresolvable-endpoint` | possible-decoy | low |
| `integrity-reference` | integrity-dependency | low |
| `bla-marker-string` | metadata-only | low |
| `electron-fuse-sentinel-flood` | resource-limit | high |
| `analyzer-error` | analysis-limitation | high |
| `js-parse-incomplete` | analysis-limitation | high |
| `js-literal-alternative-explosion` | resource-limit | high |
| `js-primitive-byte-charge` | resource-limit | high |
| `js-expression-depth` | resource-limit | medium |
| `js-getter-ring` | resource-limit | medium |
| `js-alias-table` | resource-limit | medium (>= 90% literal values) / low |
| `js-constant-guard` | possible-decoy | high |
| `js-duplicate-function-shapes` | possible-decoy | low |
| `js-dynamic-code` | reachability-unknown | high |
| `sourcemap-malformed` | analysis-limitation | high |
| `sourcemap-content-count-mismatch` | possible-decoy | medium |
| `sourcemap-index-out-of-range` | possible-decoy | high |
| `sourcemap-unreferenced-content` | possible-decoy | medium |
| `sourcemap-bundle-mismatch` | possible-decoy | high |
| `asar-invalid-header` | analysis-limitation | high |
| `asar-header-exceeds-rea-default` | resource-limit | high |
| `asar-index-unparseable` | analysis-limitation | high |
| `asar-duplicate-keys` | possible-poisoning | high |
| `asar-unsafe-member-path` | possible-poisoning | high |
| `asar-member-out-of-bounds` | analysis-limitation | high |
| `asar-malformed-entry` | analysis-limitation | high |
| `asar-overlapping-members` | possible-decoy | high |
| `asar-member-integrity-mismatch` (only with `--member`) | integrity-dependency | high |
| `wasm-bad-header` | analysis-limitation | high |
| `wasm-malformed` | analysis-limitation | high |
| `wasm-section-order` | analysis-limitation | high |
| `wasm-duplicate-exports` | analysis-limitation | high |
| `wasm-custom-sections` | metadata-only | high |
| `wasm-interface-representation` | resource-limit | high (lower bound exceeds REA limit) / medium |
| `wasm-export-inflation` | possible-decoy | medium |
| `sqlite-truncated-header` | analysis-limitation | high |
| `sqlite-header-inconsistent` | analysis-limitation | high |
| `sqlite-unreadable` | analysis-limitation | high |
| `sqlite-generated-column-unknown-function` | resource-limit | high |
| `sqlite-view-unknown-function` | reachability-unknown | medium |
| `rea-json-invalid` | analysis-limitation | high |
| `rea-json-duplicate-keys` | possible-poisoning | high |
| `rea-reported-error` | resource-limit (REA `resource_constraint` or a resource-limit catalog match) / analysis-limitation | high |
| `rea-semantic-resource-limit` | resource-limit | high |

Rules that cite pinned REA limits (`js-*` limits, `asar-header-exceeds-rea-default`, `wasm-interface-representation`, `electron-fuse-sentinel-flood`) are predictions from the catalog (`src/data/rea-failure-patterns.json`, rea-agents 6.8.0). A connected REA's own `details.limit` is authoritative.

## Additions in 0.1.0 (BLA 3.2.1 showcase)

| Rule | Class | Default confidence | Meaning |
|---|---|---|---|
| `js-alias-chain` | resource-limit | high | `v_i = cond ? v_{i-1}.p : v_{i-1}.q` chains; 2^N selector states vs REA's 512 |
| `js-dynamic-receiver-getters` | resource-limit | medium | >= 4 getters returning `this[<dynamic>].<name>` in one class/object |
| `js-folded-strings` | recovered-value | high | split strings folded soundly to <= 2 candidates over single-declaration const seeds |

`recovered-value` is a finding class for values proven statically; it says nothing about reachability. `js-constant-guard` now also covers guards proven over enumerated seed values (`x | ~x`, `Math.imul` parity identities).

### `anti-bla setup`

`anti-bla setup [--client claude,agents] [--project <dir>] [--dry-run] [--yes] [--uninstall]` copies `skills/anti-bla` to `~/.claude/skills/anti-bla` and/or `~/.agents/skills/anti-bla` (or under `--project`). It prints the plan, writes only with `--yes` or an interactive "y", backs up a differing existing copy to `anti-bla.backup-<timestamp>`, removes only directories whose SKILL.md says `name: anti-bla`, and never touches REA files or MCP configuration. Exit code 0 unless arguments are invalid (2).

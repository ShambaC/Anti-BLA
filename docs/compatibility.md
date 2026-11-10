# Compatibility record

Verified: **2026-11-10**. Every limit or behavior below points to pinned upstream source or to an output observed locally. Unknown names and changed thresholds must degrade to `unknown`; a connected REA server's own diagnostics (`details.limit`, `inspect_analysis_settings`, `tools/list` schemas) always take precedence over this file.

## Pinned upstreams

| Project | Repository | Commit | Commit date | Package | Version |
|---|---|---|---|---|---|
| REA (Reverse Engineer Anything) | https://github.com/morluto/rea | `95ebd38d3faae013a7dbf85814efa30a5c6fcf56` | 2026-11-10T06:37:51+01:00 | `rea-agents` | 6.8.0 |
| BLA (Blind LLM Agents) | https://github.com/qybaihe/bla | `38d26d52191300a127b113d44cd79ad5c97855d7` | 2026-11-10T02:13:49+08:00 | `bla-agents` | 3.2.2 |

Both are MIT-licensed. Anti-BLA contains **no** BLA or REA source code and no BLA-generated output; its fixtures are generated independently by `scripts/generate-fixtures.ts`.

## Locally installed / observed

| Item | Value |
|---|---|
| REA MCP server | `npx -y rea-agents@6.8.0 mcp` (Claude Code user config), version matches pinned `main` |
| REA skill | `reverse-engineer-anything` installed under the user's Claude skills directory (metadata version 49, 229 tools) |
| REA CLI on PATH | not installed (`rea` not found). Fetching it via `npx` was denied by the session's permission policy, so no REA CLI JSON was captured; MCP outputs were used instead. |
| Node.js | v22.21.1 (Windows 11, x64). Anti-BLA requires >= 22.13 (`node:sqlite` unflagged). Node 24/26 not tested. |
| BLA | Not installed or executed. Its source was read at the pinned commit only. |

## REA facts confirmed in source (commit 95ebd38)

| Fact | Value | Source |
|---|---|---|
| JS primitive candidates | 256 | `src/domain/javascript/javascriptSemanticResourceLimits.ts` `SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT` |
| JS expression depth | 256 | same file, `SEMANTIC_EXPRESSION_DEPTH_LIMIT` |
| JS getter expansion | 512 | same file, `SEMANTIC_GETTER_EXPANSION_LIMIT` |
| JS alias selections | 512 | same file, `SEMANTIC_ALIAS_SELECTION_LIMIT` |
| JS primitive JSON bytes | 1,048,576; charge `(len(l)+len(r))*6+2` per addition pair | same file, `exceedsSemanticPrimitiveAdditionByteBudget` |
| JS unknown shape | `{status:"unknown", reason, resourceLimit}`; reasons are fixed strings (e.g. "Primitive candidate budget exceeded (maximum 256 alternatives).") | same file, `RESOURCE_LIMIT_REASON` |
| WASM interface representation | 33,554,432 bytes | `src/domain/wasm/wasmInterface.ts` `WASM_INTERFACE_REPRESENTATION_BYTES` |
| ASAR header admission | default 16 MiB, setting max 256 MiB; compares Pickle `headerBytes` (u32 at offset 4) | `src/domain/analysisResourceLimits.ts`, `src/artifacts/AsarHeader.ts` |
| ASAR setting | `asar.max_header_bytes`, env `REA_ASAR_MAX_HEADER_BYTES`, applies `next_operation` | `src/domain/analysisSettingDefinitions.ts` |
| Electron fuse sentinel | `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`; max 32 per slice | `src/domain/electron/electronFuses.ts`, `src/electron/ElectronFuseReader.ts` |
| SQLite limits / reasons | input 256 MiB; `column-evaluation` → `capability_unavailable` with REA remediation "use schema_scope: database" | `src/sqlite/SqliteDatabaseLimits.ts`, `src/sqlite/SqliteDatabaseWorkerExecution.ts` |
| Evidence record | fields `evidence_id` (`ev_` + 64 hex), `subject`, `provider`, `operation`, `parameters`, `normalized_result`, `confidence`, `authority`, `limitations`, `relationship_coverage`, `locations`, `evidence_links`, … | `src/domain/evidence.ts` |
| Error projection | `{code, category, message, retryable, remediation:{action}, recovery?, details?}`; codes listed in `src/rea/evidence-schema.ts` | `src/contracts/errorSchemas.ts` |

These values are stored in `src/data/rea-failure-patterns.json` with `upstream_version` and `verified_at`.

## REA behavior observed over MCP (2026-11-10, rea-agents 6.8.0, Node 22.21.1)

| Call | Target (owned) | Observed |
|---|---|---|
| `analyze_javascript_application` (`detail: summary`) | generated ASAR, `headerBytes` 16,781,416 | Error `code: "truncated"`, `category: "truncated"` (not `resource_constraint`), `details.limit` = `{setting:"asar.max_header_bytes", effective_value:16777216, source:"default", unit:"bytes", minimum:1, maximum:268435456, applies_at:"next_operation", agent_editable:true, scope:"rea-runtime", rea_restart_required:false}`. **No `required_value`.** Saved: `tests/fixtures/rea/asar-admission-error.mcp.json`. |
| `update_analysis_settings` set 16,781,416 → retry once | same | Success; summary Evidence `ev_072ffcf5…`, parent `ev_a72bf96d…`, application coverage `complete`. Setting reset afterwards (revision 2, back to 16 MiB). |
| `analyze_javascript_application` (`detail: summary`) | owned JS app with ternary explosion, getter ring, alias table | Summary Evidence `ev_2ff798a1…` (parent `ev_2c3a1f33…`); limitations include "Primitive candidate budget exceeded (maximum 256 alternatives)." and "Semantic expression depth budget exceeded (maximum 256 nested expressions)."; application coverage `partial`. **No** getter-expansion or alias-selection limit was reported for the getter-ring/alias-table files. |
| `inspect_wasm_artifact` | generated 6 MB WASM | `capability_unavailable` / `unsupported_provider`: `REA_WABT_BIN_DIRECTORY` not configured (needs WABT 1.0.42). REA's WASM capacity path was therefore **not** exercised. |
| `inspect_sqlite_database` | trap fixture | `capability_unavailable`: requires Node.js >= 24.15 (24.x) or 26+ for `DatabaseSync.limits`. REA's column-evaluation path was **not** exercised. |
| `export_evidence_bundle` | session | Bundle with top-level `artifacts`, `captures`, `environments`, `providers`, `records`, `scenarios`, `unknowns`; 4 records. Saved path-redacted as `tests/fixtures/rea/session-bundle.redacted.json` (record IDs kept; IDs no longer authenticate after redaction). |

## Corrections to the implementation plan

- The plan's example implies ASAR admission errors are `resource_constraint`; REA 6.8.0 reports them as `truncated` with `details.limit`. Anti-BLA matches on `details.limit.setting` first, exact message text second, never on the code alone.
- REA's `details.limit` uses `effective_value` (not `value`) and may omit `required_value`. Anti-BLA then tells the agent to measure the header with `anti-bla inspect` instead of guessing.
- REA 6.8.0 `inspect_sqlite_database` needs Node >= 24.15; `inspect_wasm_artifact` needs a configured WABT 1.0.42. Neither is a property of the artifact.

## Not verified

- Codex or other non-Claude agent clients loading `skills/anti-bla` (no such client exercised).
- REA CLI JSON output (`rea ... --json`), REA on Node 24/26, REA WABT and SQLite providers.
- Running BLA itself on the fixtures (`bla harden`/`protect` were never run).
- macOS and Linux runs of Anti-BLA (CI matrix covers them once pushed; not run locally).

## BLA showcase run (2026-11-10)

- `bla-agents@3.2.1` was installed from npm with `npm install --no-save` (3.2.2 is on GitHub `main` but not yet published). It was run only as `bla protect <owned file> -o <out> --intensity bankrupt --seed anti-bla-showcase`. The hardened output was never executed.
- REA 6.8.0 on the hardened JS app: application `partial`, limits alias-selections, getter-expansion, primitive-bytes, primitive-candidates (1,951 semantic unknowns). On the clean original: `complete`, no limits.
- REA on the hardened ASAR (header 17,443,968 B): `truncated` admission error. After `asar.max_header_bytes` = 17,443,968 and one retry: admitted (3 JS files parsed, partial semantics). The setting was reset afterwards (revision 4).
- Results: `benchmarks/results/bla-showcase-2026-11-10.json`; reproducible Anti-BLA part: `benchmarks/bla-showcase.ts`.

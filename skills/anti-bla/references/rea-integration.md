# REA integration

Anti-BLA is a CLI overlay. It never calls REA, never edits REA's skill or config, and never registers an MCP server. Tool names cannot collide with REA's because Anti-BLA exposes none. Route analysis through the REA skill first. For REA behavior, link to REA instead of restating it:
- Pinned guides (commit 95ebd38): https://github.com/morluto/rea/blob/95ebd38d3faae013a7dbf85814efa30a5c6fcf56/.agents/skills/reverse-engineer-anything/references/javascript-applications.md, `evidence-workflows.md` and `connection-and-recovery.md` in the same folder.
- Limits and recovery design: https://github.com/morluto/rea/blob/95ebd38d3faae013a7dbf85814efa30a5c6fcf56/docs/design/limits-and-recovery.md

## Before every hinted call

1. Read the connected server's `tools/list`. Confirm the operation exists and advertises each hinted field. Refresh the list if it may be stale.
2. Treat `parametersHint` and `prerequisites` in `anti-bla` output as advisory. Satisfy every prerequisite.
3. On invalid arguments, fix the reported fields from the live schema. Do not repeat an unchanged call.
4. Read REA's own `details.limit`, bounds and `remediation.action` verbatim. They override the pinned catalog (`src/data/rea-failure-patterns.json`).
5. Tool-name prefixes belong to the client. Find the canonical operation in the actual listing before concluding it is absent.

## Prefer retained Evidence over rerunning

- Reuse a producer's Evidence with `{"kind":"retained-evidence","evidence_id":"ev_<64 hex>"}` in `inspect_analysis_view` (`source`) and in tools that take application input. Use the exact ID REA returned on the same connection. Never invent an ID.
- A `summary` Evidence cites its parent in `normalized_result.parent_evidence_id`. The parent holds the complete analysis; the summary is a view.
- Oversized transport results give `details.reported_limits.evidence_reference`. Open it with `inspect_analysis_view` for a summary, one module, or a page.
- `close_binary` clears retained references. Export first.
- A client can truncate a successful result without a REA error. Treat truncation notices and incomplete JSON as a display limit, not coverage.

## Saving REA JSON for `anti-bla rea-evidence`

Choose the file path yourself. Save only REA's returned JSON, never target text copied by hand.
- MCP error or result: save the returned JSON to a file you pick (for example in the scratchpad), then `anti-bla rea-evidence <file.json> --json`.
- Whole session: `export_evidence_bundle` to an absolute path you choose, then pass that file. Export before `close_binary`.
- Several files are accepted: `anti-bla rea-evidence a.json b.json --json`.
- `rea-evidence` keeps Evidence IDs, limits, unknowns and coverage pointers. It never opens paths found inside the JSON. Duplicate keys raise `rea-json-duplicate-keys`.
- Suggested steps are conditional. Two or more identical failures yield a `stop` action first.

## MCP versus REA CLI

- MCP failures carry `details.limit` with `scope: "rea-runtime"`. Apply with `update_analysis_settings` (takes effect at the next operation). Reset afterwards with action `reset`.
- REA CLI failures report scope `rea-invocation`. The value applies to the next invocation through an environment seed (for example `REA_ASAR_MAX_HEADER_BYTES`) or a per-call parameter. Anti-BLA emits a `manual-review` action for this, not an `update_analysis_settings` call.
- Static JS `analysis_timeout_ms` is per source and in milliseconds. A host deadline ("timed out awaiting tools/call") is separate; see [budget-recovery.md](budget-recovery.md).

## Coexistence rules

- Never edit REA's skill, config, MCP registration or settings files. Change analysis settings only through `update_analysis_settings`, with justification, within the error's bounds and the user's resource policy.
- Do not run `rea doctor`, setup or installs unless REA is missing or broken.
- Evidence IDs come from REA only. Label facts from `anti-bla` or ordinary shell tools as such, never as REA Evidence.
- Match digests. Different SHA-256 values mean different artifacts; do not merge their findings.
- Without REA, say that decompilation, application graphs and Evidence IDs are unavailable.

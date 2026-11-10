# Format playbooks

Run REA first with the smallest correct tool. Use these procedures when REA is blocked, unavailable, or when you need byte/AST provenance. Commands never execute, modify or extract the target. Add `--json`; `--output <file>` writes atomically; `--redact-paths` hides absolute paths. Budget flags: `--max-files --max-file-bytes --max-total-bytes --max-time-ms --max-depth --max-findings`. Exit code 0 includes `partial` and `unsupported`; 1 means `failed`; 2 means a usage error. Check `analysisStatus`, `coverage.excluded`, `limitations` and `unknowns` before trusting a clean result.

General: `anti-bla triage <file-or-dir> --json`; one format: `anti-bla inspect <file> --format <auto|javascript|typescript|source-map|asar|wasm|sqlite|generic> --json`.

## JS and TS

- Command: `anti-bla inspect app.js --json`.
- `js-literal-alternative-explosion`: literal alternatives from `?:` chains and string products exceed 256. REA reports "Primitive candidate budget exceeded". Decision: use `inspect_analysis_view`; the values in that expression stay unknown.
- `js-primitive-byte-charge`: estimated charge against 1,048,576 bytes.
- `js-expression-depth`: nesting over 256 (medium confidence; counting differs from REA's).
- `js-getter-ring`: `get a(){return this.b}` cycles only. A prediction, not a confirmed REA failure.
- `js-alias-table`: object literal over 512 properties read through dynamic keys. Low confidence under 90% literal values. A prediction. Real lookup tables trip it.
- `js-constant-guard`: guard built purely from literals is constant. Do not report the dead arm as behavior; do not delete it.
- `js-duplicate-function-shapes`: possible chaff; reachability unknown.
- `js-dynamic-code`: `eval`/`Function` present; reachability unknown.
- `js-parse-incomplete`: parse failed or timed out. Structure is unknown, not clean.
- Stays unknown: runtime values, call-graph reachability, predicates over variables, anything past the read budget.

## Source maps

- Command: `anti-bla triage <dir containing bundle and .map> --json`. Pairing needs the bundle in the same scan or an inline map.
- `sourcemap-bundle-mismatch`: `sourcesContent` does not match the emitted bundle. Trust the bundle.
- `sourcemap-unreferenced-content`: content no mapping references (honey map candidate).
- `sourcemap-index-out-of-range`, `sourcemap-content-count-mismatch`: structurally inconsistent map.
- `sourcemap-malformed`: unparsed; map contents unknown.
- Decision: a map is a developer assertion until checked against the bundle (see [evidence-validation.md](evidence-validation.md)). REA `compare_source_to_bundle` is the REA-side check.
- Stays unknown: whether the map describes the shipped build.

## ASAR

- Command: `anti-bla inspect app.asar --json`. Read `facts.headerBytes`, `headerToDataRatio`. Nothing is extracted. `--member <path>` reads one member into memory, hashes and scans it.
- `asar-header-exceeds-rea-default`: header over 16,777,216 bytes. Recovery: [budget-recovery.md](budget-recovery.md).
- `asar-invalid-header`, `asar-index-unparseable`: no inventory; members unknown.
- `asar-duplicate-keys`: different parsers see different content; poisoning risk.
- `asar-unsafe-member-path`: zip-slip names or links. Never extract naively.
- `asar-member-out-of-bounds`, `asar-malformed-entry`: member unreadable.
- `asar-overlapping-members`: names alias the same bytes; inventories over-count.
- `asar-member-integrity-mismatch`: only with `--member`; the member differs from its recorded digest.
- Stays unknown: `.asar.unpacked` members, content beyond the scan window, integrity enforcement.

## WASM

- Command: `anti-bla inspect m.wasm --json`. The module is never instantiated; only `WebAssembly.validate` runs.
- `wasm-interface-representation`: lower-bound charge (1024 + 6 x name bytes per entry) against 33,554,432. A miss does not prove REA admits it.
- `wasm-export-inflation`: over 64 exports and over 4 times the defined functions. An export name does not show the JS side calls it.
- `wasm-custom-sections`: non-toolchain sections are metadata only. Read as data.
- `wasm-duplicate-exports`, `wasm-section-order`, `wasm-malformed`, `wasm-bad-header`: framing problems; later sections unknown.
- REA `inspect_wasm_artifact` needs WABT 1.0.42; `capability_unavailable` is environmental.
- Stays unknown: function bodies, signatures beyond the budget, component-model modules.

## SQLite

- Command: `anti-bla inspect db.sqlite --json`. Catalog only (`sqlite_master`, `pragma_function_list`, `pragma_table_xinfo`); user tables are never queried.
- `sqlite-generated-column-unknown-function`: a generated column calls a function missing from the local SQLite build. May be a legitimate app function. Matches REA's column-evaluation failure.
- `sqlite-view-unknown-function`: reachability unknown.
- `sqlite-truncated-header`, `sqlite-header-inconsistent`, `sqlite-unreadable`: catalog unavailable.
- WAL databases: the `-wal` sidecar is not read; recent commits may be missing.
- Stays unknown: row data, computed values, trigger behavior. REA `inspect_sqlite_database` needs Node.js >=24.15 in 24.x or 26+.

## Native and other formats

- Electron fuses: `electron-fuse-sentinel-flood` scans PE/ELF/Mach-O for the sentinel string; threshold 32. No structure parsing; fuse state unknown.
- Safetensors, GGUF, Go buildinfo, Flutter/Dart, Erlang BEAM, EVM, pcap, GPU code objects: `unsupported`. Only the generic bounded text scan runs (first 4 MiB): `agent-directed-instruction`, `credential-shaped-string`, `unresolvable-endpoint`, `integrity-reference`, `bla-marker-string`.
- Use the matching REA tool for structure. Report Anti-BLA output as string-level observation only.

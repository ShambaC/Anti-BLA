# Limitation matrix

Status values: implemented (a rule detects the pattern as stated), partial (a narrower or heuristic check exists), unsupported (no dedicated detection). Rule ids are defined in `docs/tool-contracts.md`. A finding is a prediction from static evidence and pinned REA 6.8.0 limits, not proof of BLA or of a REA failure.

| BLA technique family | Status | Rule id / notes |
|---|---|---|
| JS primitive-candidate explosion (literal alternatives) | implemented | `js-literal-alternative-explosion`. Counts literal alternatives from `?:` chains and string concatenation products; threshold 256 (REA `js.primitiveCandidates`). Literal leaves only; a non-literal leaf ends the count. |
| JS primitive-byte charge | implemented | `js-primitive-byte-charge`. Uses REA's `(len(l)+len(r))*6+2` charge against 1,048,576 bytes. |
| JS expression depth | implemented | `js-expression-depth`. Threshold 256. Anti-BLA's depth count is not identical to REA's, so confidence is medium. |
| Getter rings | partial | `js-getter-ring`. Detects only `get a(){return this.b}` cycles. Other recursion shapes are missed. Prediction only (see below). |
| Alias-selection tables | partial | `js-alias-table`. Object literal with more than 512 properties read through dynamic keys. Confidence low when under 90% of values are literals. Prediction only (see below). |
| Opaque predicates | partial | `js-constant-guard`. Only guards built purely from numeric/boolean literals are proven constant. Predicates over variables are not evaluated. |
| Call-graph labyrinths / chaff | partial | `js-duplicate-function-shapes`. Heuristic: at least 50 function bodies sharing one syntax shape and at least 10% of functions. Confidence low. No call graph is built; reachability is never established. |
| Prompt / evidence poisoning text | implemented | `agent-directed-instruction`, `analyzer-tool-reference`, `unresolvable-endpoint`. Regex rules over source, ASAR index, WASM custom sections, SQLite schema SQL, REA JSON. Wording variants not in the pattern list are missed. |
| Canary credentials | implemented | `credential-shaped-string` (shape match only, low confidence), `bla-marker-string` for known marker literals. Values are redacted and never tested. |
| Honey source maps | implemented | `sourcemap-unreferenced-content`, `sourcemap-bundle-mismatch` (needs the paired bundle in the same scan or an inline map), `sourcemap-index-out-of-range`, `sourcemap-content-count-mismatch`, `sourcemap-malformed`. |
| ASAR header inflation | implemented | `asar-header-exceeds-rea-default` (default 16,777,216; settable to 268,435,456 per catalog). |
| ASAR overlapping / unsafe members | implemented | `asar-overlapping-members`, `asar-unsafe-member-path`, `asar-member-out-of-bounds`, `asar-malformed-entry`, `asar-duplicate-keys`. Nothing is extracted. |
| WASM interface representation exhaustion | partial | `wasm-interface-representation`. Lower-bound charge (1024 + 6 x name bytes per entry); WAT text and signature terms are omitted, so a miss does not prove REA will admit it. |
| WASM custom-section decoys | implemented | `wasm-custom-sections` (non-toolchain names), plus rule scan of custom-section text. Sections are never executed. |
| WASM export inflation | implemented | `wasm-export-inflation` (more than 64 exports and more than 4 times the defined functions); also `wasm-duplicate-exports`, `wasm-section-order`, `wasm-malformed`. |
| SQLite generated-column trap functions | implemented | `sqlite-generated-column-unknown-function`, `sqlite-view-unknown-function`. Compares called function names to `pragma_function_list` of the local SQLite build. |
| Electron fuse sentinel flood | partial | `electron-fuse-sentinel-flood`. Generic scan of PE/ELF/Mach-O files for the fuse sentinel string; threshold 32 (REA). No native structure parsing. |
| Self-sealing / integrity | partial | `integrity-reference` (digest strings, low confidence); `asar-member-integrity-mismatch` only for the member chosen with `inspect --member`. Enforcement is never established. |
| Runtime deception (CDP, Frida, LLDB, GDB, rizin budgets) | unsupported | Runtime is out of scope; Anti-BLA is static and read-only. |
| Safetensors / GGUF nesting | unsupported | Detected by name/magic; generic text scan only, status `unsupported`. |
| Go buildinfo | unsupported | Generic scan only. |
| Flutter / Dart pools | unsupported | Generic scan only. |
| Erlang BEAM | unsupported | Generic scan only. |
| EVM bytecode | unsupported | Generic scan only. |
| pcap | unsupported | Generic scan only. |
| GPU PTX / code objects | unsupported | Generic scan only. |

"Generic scan only" means the bounded text/ASCII-run rule scan (first 4 MiB) applies: agent-directed text, credential shapes, endpoint strings, integrity strings and BLA markers. No format structure is parsed.

## Known false-positive sources

- Large legitimate ASAR indexes: apps with very many files can exceed 16 MiB of index. The rule reports the header-to-data ratio; a large ratio is the stronger signal.
- Generated code with many identical functions (`js-duplicate-function-shapes`, low confidence).
- Legitimate custom SQLite functions registered by the application (`sqlite-generated-column-unknown-function`).
- Electron integrity hashes: `electron-builder` and similar write `sha256` digests that match `integrity-reference`. The rule is low confidence and only says a digest string exists.
- Lookup tables in real code (`js-alias-table`), such as diagnostic registries.
- Documentation and tests that quote agent-directed phrases, tool names or sample credentials (`agent-directed-instruction`, `analyzer-tool-reference`, `credential-shaped-string`).
- Anti-BLA's own source tree contains BLA marker strings and rule patterns, so scanning it reports `bla-marker-string` and `agent-directed-instruction` findings. Do not treat that as attribution.
- Minified or bundled code can reach the nesting and alternative thresholds without any adversary.

## Observed on real REA 6.8.0 (2026-11-10)

REA reported primitive-candidates and expression-depth limits for the owned JS fixture app. The getter-ring and alias-table fixtures did NOT produce REA getter-expansion or alias-selection limits in that run, so those Anti-BLA findings (`js-getter-ring`, `js-alias-table`) are predictions, not confirmed REA failures.

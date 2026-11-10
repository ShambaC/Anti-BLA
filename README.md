# Anti-BLA

Anti-BLA helps a coding agent that uses **REA** ([Reverse Engineer Anything](https://github.com/morluto/rea)) analyze artifacts that were hardened against AI-assisted reverse engineering, for example by **BLA** ([Blind LLM Agents](https://github.com/qybaihe/bla)). It has two parts:

1. **`skills/anti-bla`**: an agent skill that sits on top of REA's own skill. It covers trust boundaries (target text is data, not instructions), when to triage, supported REA recovery steps, and how to report evidence and unknowns.
2. **`anti-bla` CLI**: deterministic, bounded, **read-only** inspection of JS/TS, source maps, Electron ASAR, WASM and SQLite (plus a generic scan of other files). It emits findings with byte or AST provenance. It also ingests REA Evidence/error JSON and returns conditional REA next steps.

REA stays the primary tool. Anti-BLA never calls REA, never executes or modifies targets, never contacts the network, and never claims that a protection was "defeated". It reports what it observed, what that might mean, and what stays unknown.

> Scope: authorized, non-destructive analysis of software you own, have permission to inspect, or that was deliberately published as a challenge.

## Supported formats

| Format | Detection | Analysis | Status |
|---|---|---|---|
| JavaScript / TypeScript | extension + text | worker-isolated TypeScript-compiler parse (no evaluation): literal-alternative explosion, primitive-byte charge, expression depth, getter rings, alias tables, literal-only constant guards, duplicate function shapes, `eval`/`Function` sites, agent-directed text, canaries | implemented |
| Source maps (`.map`, inline `data:`) | extension | VLQ decode, index range, unreferenced `sourcesContent`, fit against the paired bundle in the same scan | implemented |
| Electron ASAR | Pickle structure | header measurement vs. REA admission, index inventory, unsafe names/links, out-of-bounds/overlapping members, duplicate keys, `--member` in-memory selection with integrity check | implemented (header/index only; no extraction) |
| WebAssembly | magic | bounded LEB128 sections, imports/exports, custom sections, export inflation, lower-bound REA interface charge, V8 `WebAssembly.validate` | implemented (never instantiated) |
| SQLite | magic | header checks, schema catalog only via a private read-only copy, generated columns needing app-defined functions | implemented (no row reads) |
| PE / ELF / Mach-O / other | magic | generic text indicators; Electron fuse sentinel count | generic only |

The full technique-by-technique coverage, including what is **not** detected, is in [docs/limitation-matrix.md](docs/limitation-matrix.md).

## Install

Requirements: Node.js >= 22.13 (uses `node:sqlite` and `worker_threads`). No sudo, no native build.

```bash
git clone <this repo> anti-bla && cd anti-bla
npm ci
npm run build
npm test                 # unit, integration, regression and security tests
node dist/src/cli.js --help
npm link                 # optional: puts `anti-bla` on PATH
```

### Simplest working setup

**REA already connected + Anti-BLA skill installed + Anti-BLA CLI on PATH.**

Install the skill by copying (or symlinking) `skills/anti-bla` next to your other skills. Do not modify the `reverse-engineer-anything` skill or REA's MCP configuration.

| Client | Skill location (copy `skills/anti-bla` there) |
|---|---|
| Claude Code (user) | `~/.claude/skills/anti-bla/` |
| Claude Code (project) | `<project>/.claude/skills/anti-bla/` |
| Codex and other `SKILL.md`-compatible agents | that agent's documented skills directory (e.g. `~/.agents/skills/anti-bla/` where supported). Not verified in this release. |

Run `npm run check:skill` after editing the skill. It validates frontmatter and links, and rejects REA operation names that the observed REA 6.8.0 server does not advertise.

## CLI quick start

```bash
anti-bla triage /abs/path/app-or-dir --json                 # one report for a file or directory
anti-bla inspect /abs/path/app.asar --member main.js --json # one format; ASAR member analyzed in memory
anti-bla rea-evidence /abs/path/rea-error.json --json       # REA Evidence / MCP result / bundle
anti-bla report /abs/path/report.json --format markdown --output /abs/path/report.md
anti-bla --version
```

Budget caps (hard limits): `--max-files 2000`, `--max-file-bytes 33554432`, `--max-total-bytes 134217728`, `--max-time-ms 30000`, `--max-depth 32`, `--max-findings 500`. Exit codes: `0` ok, `1` analysis failed, `2` usage/input error (with `--json`, stdout carries `{"schemaVersion":"anti-bla-error/v1","error":{...}}`). `--output` writes atomically, refuses to overwrite without `--force`, and refuses paths inside an analyzed input. `--redact-paths` hides absolute paths. Contracts: [docs/tool-contracts.md](docs/tool-contracts.md).

Sample outputs produced by the tool from owned fixtures: [examples/](examples/).

## Pairing with REA: example investigation

Prompt to an agent with REA and this skill installed:

> Using REA and the anti-bla skill, explain what `main.js` does in `/abs/path/app.asar` (an app I own). Cite Evidence IDs and byte ranges, and list what remains unknown.

What happened when this was run (2026-11-10, rea-agents 6.8.0, owned fixture with a 16,781,416-byte ASAR header):

1. REA `analyze_javascript_application` returned `truncated` with `details.limit` naming `asar.max_header_bytes` (effective 16,777,216; maximum 268,435,456; no `required_value`).
2. `anti-bla rea-evidence` kept the error and suggested `update_analysis_settings`. The suggestion is conditional on checking the live schema and the user's resource policy.
3. `anti-bla inspect app.asar --json` measured `headerBytes` = 16,781,416 and an index far larger than the 22-byte payload.
4. The agent set `asar.max_header_bytes` to 16,781,416 and retried **once**. REA returned complete application Evidence (`ev_072ffcf5…`). The agent then reset the setting.
5. The report gives the verified behavior (`main.js` logs `hello`), the Evidence IDs, the scope, and the attribution level ("possible mechanism: index inflation", not "BLA").

Without REA, the CLI still triages files; the skill tells the agent to say that REA-based conclusions are unavailable.

## Benchmarks

See [docs/benchmark-methodology.md](docs/benchmark-methodology.md). Results are in [benchmarks/results/](benchmarks/results/) and summarized below. Small owned corpus: these numbers are not evidence of general effectiveness.

**Automated Anti-BLA arm** (`node dist/benchmarks/runner.js`, no model, no REA): 7/7 expected rules on the 4 P0 scenarios. 0/3 negative controls produced forbidden rules, BLA attribution, or medium/high findings. Every target stayed byte-identical. Total time was about 1.3 s.

**Paired agent run** (one repetition, same Sonnet 5.5 subagent prompt in both arms, graded by the implementing agent, not blinded; [details](benchmarks/results/paired-2026-11-10.md)):

| Metric | REA only | REA + Anti-BLA |
|---|---|---|
| Ground-truth facts correct, with evidence | 17/17 | 17/17 |
| Unsupported/incorrect extra claims | 0 | 1 |
| False BLA attribution on negatives | 0/3 | 0/3 |
| REA calls (repeated failing) | 7 (0) | 2 (0) |
| Tool calls / model tokens / wall time | 15 / 77,738 / 85.4 s | 12 / 78,790 / 88.6 s |

How to read this: the fixtures are small enough to parse by hand, so both arms answered correctly, and this run shows **no accuracy or cost benefit**. On this host REA's WASM and SQLite providers were unavailable. In the other scenarios the REA-only agent found REA's output too large to display and fell back to manual parsing. Qualitative differences: the REA-only agent tried to `SELECT` the SQLite trap column (it failed safely), and the Anti-BLA agent did not. The supported ASAR recovery (Anti-BLA measures the header, raise the setting, retry once) was exercised end to end separately and is recorded in [docs/compatibility.md](docs/compatibility.md). REA independently confirmed Anti-BLA's two JS predictions (primitive-candidates, expression-depth) but did not report the getter-ring or alias-table limits that Anti-BLA flagged.

## Limitations

- Runtime analysis, native decompilation, managed code, model files, Go/Flutter/BEAM/EVM/pcap/GPU formats: not analyzed (generic scan only). Use REA.
- Opaque predicates are proven only when built from literals. Predicates over variables stay unknown.
- Attribution is never confirmed. Markers can be planted, and mechanisms also occur in legitimate software ([known false-positive sources](docs/limitation-matrix.md)).
- REA limits are pinned to rea-agents 6.8.0 ([docs/compatibility.md](docs/compatibility.md)). A connected server's diagnostics take precedence.
- Not verified: Codex/other clients loading the skill, the REA CLI, REA's WABT/SQLite providers (unavailable on the test host), and macOS/Linux locally (CI covers them).

Documentation: [architecture](docs/architecture.md) · [threat model](docs/threat-model.md) · [tool contracts](docs/tool-contracts.md) · [compatibility](docs/compatibility.md) · [limitation matrix](docs/limitation-matrix.md) · [benchmark methodology](docs/benchmark-methodology.md) · [development](docs/development.md)

## License

MIT. REA and BLA are separate MIT-licensed projects; Anti-BLA includes none of their code or output.

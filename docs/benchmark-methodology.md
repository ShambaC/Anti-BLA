# Benchmark methodology

Anti-BLA is measured, not estimated. BLA's showcase token multipliers are internal estimates by BLA's authors; this project never reuses them. Every number in `benchmarks/results/` comes from an actual run, and fields a host did not expose are recorded as `null` ("not measured").

## Corpus

`benchmarks/scenarios.json` lists 4 P0 scenarios and 3 negative controls. All targets are owned fixtures from `scripts/generate-fixtures.ts`: no BLA code, no BLA output, no third-party CrackMe. Ground truth is known by construction (for example, the ternary fixture's `secret` is fixed because every guard is a literal-only constant).

| Scenario | Kind | What it exercises |
|---|---|---|
| `p0-asar-header` | P0 | ASAR index inflated past REA's 16 MiB default admission |
| `p0-js-candidates` | P0 | literal ternary/concatenation explosion + constant guards (REA primitive-candidates / expression-depth) |
| `p0-wasm-decoy` | P0 | 300 aliased exports, canary credentials and agent-directed text in custom sections |
| `p0-sqlite-trap` | P0 | VIRTUAL generated column calling an application-only function, injection text in schema |
| `neg-clean-asar` | negative | ordinary Electron-style archive |
| `neg-minified-js` | negative | ordinary minified CommonJS library |
| `neg-clean-sqlite` | negative | generated column using a built-in function |

**Threat to validity:** the fixtures are small and hand-parsable. A capable agent can answer them by reading bytes directly, so they measure discipline (evidence, unknowns, attribution, wasted calls) more than raw recovery power. A larger corpus with authorized real applications hardened by BLA is the next step (see "Not done").

## Arms

1. **Automated Anti-BLA arm** — `node dist/benchmarks/runner.js`. Runs `anti-bla triage --json` on each materialized scenario and compares emitted rule ids with `expectAntiBla.rules` (expected) and `forbidRules` (false positives). Records wall time, analysis status, attribution, and verifies target hashes are unchanged. No model, no REA. Output: `benchmarks/results/antibla-auto-latest.{json,md}`.
2. **Paired agent arms** — the same agent model answers every scenario question twice under identical prompts and limits:
   - `rea-only`: REA MCP tools + generic read-only file inspection.
   - `rea+anti-bla`: the same, plus the `anti-bla` skill and CLI.
   Targets are materialized with `node dist/benchmarks/runner.js --materialize <dir>` into a directory outside the repository, so agents cannot read ground truth from fixtures or generator source. Both prompts forbid executing or modifying targets and forbid reading the Anti-BLA source tree (arm B may read only `skills/anti-bla/` and run the CLI).

## Recording and grading

Results go to `benchmarks/results/paired-<date>.json` (schema `anti-bla-paired-results/v1`) and are checked with:

```bash
node dist/benchmarks/validate-results.js benchmarks/results/paired-<date>.json
```

The validator rejects missing arms, mismatched scenario sets, facts that do not match `groundTruth` ids, "verified-correct" outcomes with missing/incorrect facts, and non-numeric usage fields. It writes the Markdown summary next to the JSON.

Per scenario and arm the grader records:

- each ground-truth fact: `correct` / `incorrect` / `missing` / `reported-unknown-correctly`, and whether the answer cited evidence (REA Evidence ID, byte offset or line);
- `unsupportedClaims`: conclusions without supporting evidence;
- `reaCalls`, `repeatedFailingCalls` (identical failing call repeated);
- `blaAttributionClaimed` (`none` / `mechanism` / `bla`) — "bla" on a negative control is a false attribution;
- `reportedPartial` — whether partial evidence was reported as partial.

Usage per arm (`modelTokens`, `toolCalls`, `wallTimeMs`) is copied from the host's task-completion report for that agent run. When a host does not expose a value it stays `null`.

## Metrics

Evidence-backed correctness, incorrect/missing facts, unsupported claims, false BLA attribution on negatives, REA calls, wasted retries, outcome distribution, and the observed usage. Metrics are computed only from recorded fields.

## Not done (honest gaps)

- n = 1 repetition per arm; no confidence intervals. Results are anecdotal.
- Grading by the implementing agent, not blinded and not independent.
- REA WASM (WABT 1.0.42) and SQLite (Node >= 24.15) providers were unavailable on the benchmark host, so REA could not contribute to those scenarios in either arm.
- BLA was not run to harden a real application; BLA CrackMe v6-v9 were not attempted (they would be external opt-in tests and their offline answers are not public).
- Peak memory was not measured.

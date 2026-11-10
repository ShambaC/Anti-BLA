# Automated Anti-BLA arm (latest run)

Ran 2026-11-10T06:21:46.678Z on win32 10.0.26200 x64, Node v22.21.1, anti-bla 0.1.0, catalog rea-agents@6.8.0 (95ebd38d3faa).

- P0 expected-rule recall: 7/7
- Negative controls with forbidden rules: 0/3
- Negative controls with any BLA attribution: 0/3
- Negative controls with medium/high findings: 0/3
- All targets byte-identical after analysis: true
- Total wall time: 1332 ms

| Scenario | Kind | Status | Attribution | Missing expected | Forbidden present | ms |
|---|---|---|---|---|---|---|
| p0-asar-header | p0 | complete | bla-like-mechanisms | - | - | 470 |
| p0-js-candidates | p0 | complete | bla-like-mechanisms | - | - | 299 |
| p0-wasm-decoy | p0 | complete | bla-markers-observed | - | - | 66 |
| p0-sqlite-trap | p0 | complete | bla-like-mechanisms | - | - | 64 |
| neg-clean-asar | negative-control | complete | none-observed | - | - | 58 |
| neg-minified-js | negative-control | complete | none-observed | - | - | 307 |
| neg-clean-sqlite | negative-control | complete | none-observed | - | - | 68 |

_Small owned corpus (4 P0 + 3 negative controls); not evidence of general accuracy._

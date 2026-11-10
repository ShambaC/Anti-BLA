<div align="center">

# Anti-BLA

### See through anti-AI hardening. Keep REA working.

**A read-only overlay for [REA](https://github.com/morluto/rea). It recognizes artifacts hardened against AI reverse engineering (such as [BLA](https://github.com/qybaihe/bla)), measures each trap, and gets the analysis moving again with evidence for every step.**

[![npm](https://img.shields.io/npm/v/anti-bla?style=flat-square&color=cb3837)](https://www.npmjs.com/package/anti-bla)
[![Node.js >= 22.13](https://img.shields.io/badge/Node.js-%3E%3D22.13-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#quick-start)
[![Works with REA 6.8](https://img.shields.io/badge/REA-6.8.0-5c4ee5?style=flat-square)](docs/compatibility.md)
[![Tested against BLA 3.2.1](https://img.shields.io/badge/BLA-3.2.1_tested-b31b1b?style=flat-square)](#results-against-real-bla)
[![Agent skill](https://img.shields.io/badge/agent-skill-0a7bbb?style=flat-square)](skills/anti-bla/SKILL.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

[Quick start](#quick-start) · [Results against real BLA](#results-against-real-bla) · [How it works](#how-it-works) · [What it analyzes](#what-it-analyzes) · [FAQ](#faq) · [Documentation](#documentation)

<code>npx anti-bla setup</code>

</div>

## Quick start

Anti-BLA sits on top of REA. If you do not have REA yet, run `npx rea-agents setup` first ([REA quick start](https://github.com/morluto/rea#quick-start)).

### Set up your agent

With Node.js >= 22.13, run:

```bash
npx anti-bla setup
```

Setup shows its plan before writing anything. It installs the `anti-bla` skill next to your other agent skills, in the same places REA's setup uses:

| Agent                                                                              | Skill location              |
| ---------------------------------------------------------------------------------- | --------------------------- |
| Claude Code                                                                        | `~/.claude/skills/anti-bla` |
| Codex, Cursor, Gemini CLI and other [Agent Skills](https://agentskills.io) clients | `~/.agents/skills/anti-bla` |

Use `--project <dir>` to install into one project instead, `--dry-run` to preview, `--yes` to skip the prompt, and `--uninstall` to remove the skill. An existing modified copy is backed up first. Setup never edits REA, its skill, or any MCP configuration. Restart your agent afterward.

<details>
<summary><strong>Other ways to install</strong></summary>

<br />

| Route                                       | Command                                                                                                                      |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Skills CLI ([skills.sh](https://skills.sh)) | `npx skills add ShambaC/anti-bla`                                                                                            |
| Claude Code plugin                          | `/plugin marketplace add ShambaC/anti-bla`, then `/plugin install anti-bla@anti-bla`                                         |
| Codex plugin                                | install from this repository (`.codex-plugin/plugin.json` points at `./skills`)                                              |
| Manual                                      | copy `skills/anti-bla/` into your agent's skills directory                                                                   |
| Ask your agent                              | _"Install the Anti-BLA skill from https://github.com/ShambaC/anti-bla by running `npx anti-bla setup --yes`, then restart."_ |
| From source                                 | `git clone https://github.com/ShambaC/anti-bla && cd anti-bla && npm ci && npm run build && node dist/src/cli.js setup`                                                       |

The CLI itself needs no installation: the skill calls `anti-bla` when it is on PATH (`npm install -g anti-bla`) and otherwise uses `npx -y anti-bla`.

</details>

### Ask your agent

```text
Understand how the license check works in the Notes app. If REA stalls or the code fights back,
use the anti-bla skill, recover what you can, and show me the evidence and what stays unknown.
```

Replace "the Notes app" with an app you own or are authorized to analyze, and "the license check" with the feature you want to understand. You do not need to name Anti-BLA every time. The skill loads on its own when REA hits a capacity limit or the target contains decoys or text aimed at the agent.

### Use the terminal

Triage an extracted app directory, an ASAR, or any single file:

```bash
npx -y anti-bla triage /absolute/path/to/app --json
```

The report lists each artifact's SHA-256, the traps it found with byte or AST locations, decoded values, suggested REA next steps, and what stays unknown. Replace the path with your target, such as `"D:/apps/example"` on Windows.

More commands:

```bash
npx -y anti-bla inspect <file> [--member <path-in-asar>]   # one file; one ASAR member analyzed in memory
npx -y anti-bla rea-evidence <saved-rea-output.json>      # turn a REA error or Evidence record into supported next steps
npx -y anti-bla report <report.json> --format markdown    # render a stored report
```

To install the `anti-bla` command for regular use, run `npm install --global anti-bla`, then `anti-bla --help`. Add `--json` for machine-readable output. All commands are read-only: targets are never executed, modified or extracted, and nothing is sent over the network.

## Results against real BLA

We wrote a small app with a known answer, hardened it with **real `bla-agents@3.2.1`** (`bla protect --intensity bankrupt`), and asked the same question three ways: REA on the clean original, REA alone on the hardened copy, and REA guided by Anti-BLA. REA is `rea-agents@6.8.0` over MCP. The hardened files were never executed.

| Target                     | BLA hardening                  | REA alone                                                                                                                          | REA + Anti-BLA                                                                                                                                                                 |           Recovered           |
| :------------------------- | :----------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------: |
| **License gate** (`.js`)   | 422 B → **136 KB**             | ⚠️ partial: 4 semantic budgets hit (alias-selections, getter-expansion, primitive-bytes, primitive-candidates), **1,951 unknowns** | All 4 traps located. **31** opaque guards proven constant, **5** split strings decoded: `Acme Notes`, `string`, `pro`, `basic`, `free`                                         |       ✅ rules + tiers        |
| **Electron app** (`.asar`) | 1.1 KB → **18.2 MB** index     | ❌ refused: `truncated`, header admission 16 MiB, no required size given                                                           | Measured header **17,443,968 B**, set `asar.max_header_bytes`, retried **once**: analysis admitted. Decoded IPC channel `notes:quota` and bridge `notes` that REA left dynamic |      ✅ channel + bridge      |
| **WebAssembly** (`.wasm`)  | 41 B → **6.9 MB**, 251 exports | ❌ provider unavailable here (WABT 1.0.42 not configured)¹                                                                         | **251 exports → 1 real function** (9-byte body, exact byte range). 9 decoy custom sections, canary credentials flagged and redacted                                            | 🟡 body located, read by hand |
| **SQLite** (`.sqlite`)     | 8 KB → 53 KB, 5 honey tables   | ❌ provider unavailable here (needs Node ≥ 24.15)¹                                                                                 | Real table `licenses` identified. 3 trap columns on `enclave_unseal_payload()` isolated to decoy tables; nothing evaluated                                                     |        ✅ schema level        |

Clean controls: Anti-BLA ran on the four unhardened originals and reported **0** medium/high findings and attribution `none-observed`. Anti-BLA's own wall time is **< 1 s** for all four hardened targets.

<sub>¹ BLA's own report shows REA hitting `WASM_INTERFACE_REPRESENTATION_BYTES` and `SqliteColumnEvaluationFailure` when those providers are installed. We did not reproduce that here, and we do not claim it.</sub>

<details>
<summary><strong>What "recovered" means, and what it does not</strong></summary>

<br />

- **Decoded strings** come from sound static folding: literals, bitwise operations, `Math.imul` and `?:`, evaluated across every possible value of BLA's runtime seed. BLA ties one seed bit to a runtime digest check, so each string folds to at most two candidates. The report lists both (e.g. `Acme Notes` or `A8me2No9es`).
- **Opaque guards** such as `(Math.imul(x|85,(x|85)+1)&1)===0` are proven constant for every possible seed value, not guessed.
- **REA's semantic budgets stay hit.** Anti-BLA does not raise or bypass them; there is no supported setting for them. Anti-BLA answers the question from its own evidence and keeps REA's unknowns in the report.
- One run, single operator, graded against known ground truth. Machine-readable record: [`benchmarks/results/bla-showcase-2026-11-10.json`](benchmarks/results/bla-showcase-2026-11-10.json).

</details>

Reproduce it:

```bash
git clone https://github.com/ShambaC/anti-bla && cd anti-bla
npm ci
npm install --no-save bla-agents@3.2.1   # BLA is only needed to build the hardened samples
npm run bench:bla                        # hardens the owned samples in a temp dir and runs Anti-BLA on both sets
```

The run writes `benchmarks/results/bla-showcase-latest.json`. The REA columns come from REA over MCP and are recorded in [`benchmarks/results/bla-showcase-2026-11-10.json`](benchmarks/results/bla-showcase-2026-11-10.json).

<details>
<summary><strong>Earlier paired agent run on owned fixtures (no BLA)</strong></summary>

<br />

The same Sonnet subagent answered 7 questions twice (4 hardened-style fixtures and 3 clean controls), once with REA only and once with REA + Anti-BLA. Both arms got **17/17** facts right on these small, hand-parsable fixtures, so this run shows **no accuracy or token benefit**: 77,738 vs 78,790 tokens, 85 s vs 89 s. Arm B made 2 REA calls versus 7. The REA-only agent tried to `SELECT` the SQLite trap column; the Anti-BLA agent did not. Details: [`benchmarks/results/paired-2026-11-10.md`](benchmarks/results/paired-2026-11-10.md).

</details>

## How it works

```text
 your question ──► REA (primary tool) ──► result, partial result, or capacity error
                         ▲                       │
                         │                       ▼
       one supported setting / narrower    anti-bla triage | inspect | rea-evidence
       scope / retained-Evidence view        • fingerprint (SHA-256), bounded read-only parse
       (schema-checked by the agent)         • measure the trap (header bytes, 2^N selector states,
                         ▲                     candidate counts, trap functions, decoy sections)
                         │                   • fold opaque guards and split strings soundly
                         └──── next step ◄── • quote poisoned text as untrusted data, never obey it
                                             • report: observed / inferred / unknown, with byte, AST
                                               or REA Evidence provenance for every finding
```

- **The skill instructs and the CLI computes.** REA stays the primary tool. Anti-BLA never calls REA, never patches anything, and never claims a protection was "defeated".
- **Attribution has three levels:** `none-observed`, `bla-like-mechanisms` and `bla-markers-observed`. A REA capacity error alone is never called BLA.
- **Recovery is supported only.** Anti-BLA suggests documented REA settings within REA's own bounds, then one retry. A repeated identical failure is a stop.

## What it analyzes

| Format                                                              | What Anti-BLA measures                                                                                                                                                                             | Status  |
| :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----: |
| **JavaScript / TypeScript**                                         | literal-alternative explosions, primitive-byte charge, expression depth, alias chains and tables, getter rings and dynamic-receiver getters, opaque guards, split strings, `eval`/`Function` sites |   ✅    |
| **Source maps**                                                     | VLQ validity, out-of-range sources, `sourcesContent` that no mapping uses, fit against the emitted bundle                                                                                          |   ✅    |
| **Electron `.asar`**                                                | header vs. REA admission, index inventory, unsafe/escaping names, overlapping or out-of-bounds members, duplicate keys, `--member` analysis with integrity check                                   |   ✅    |
| **WebAssembly**                                                     | bounded LEB128 sections, import/export inventory, export aliasing, custom-section decoys, lower-bound REA interface charge                                                                         |   ✅    |
| **SQLite**                                                          | header checks, schema-only catalog from a private read-only copy, generated columns that need application functions                                                                                |   ✅    |
| **PE / ELF / Mach-O / other**                                       | poisoned text, canary credentials, Electron fuse-sentinel floods                                                                                                                                   | generic |
| Runtime, native decompilation, models, Go/Flutter/BEAM/EVM/pcap/GPU | use REA directly                                                                                                                                                                                   |    —    |

Every technique, including what is **not** detected, is listed in the [limitation matrix](docs/limitation-matrix.md).

## FAQ

<details>
<summary><strong>Does Anti-BLA replace REA?</strong></summary>

No. REA does the reverse engineering. Anti-BLA spots when an artifact is fighting the analysis, measures how, and tells the agent which supported REA step to try next. Without REA, the CLI still triages files, and the skill tells the agent to say that REA-based conclusions are unavailable.

</details>

<details>
<summary><strong>Is it safe to run on hostile files?</strong></summary>

It is built for hostile input. Anti-BLA does not execute, `require` or instantiate targets, and does not evaluate SQLite columns. Reads are bounded and every regex quantifier is bounded. JS parsing runs in a resource-limited worker. Prompt-injection text is quoted as data and never obeyed, and apparent secrets are redacted. See the [threat model](docs/threat-model.md).

</details>

<details>
<summary><strong>Can it be fooled?</strong></summary>

Yes. Detection is structural and versioned against REA 6.8.0 and BLA 3.2.1. New hardening shapes can slip past it, markers can be planted, and large legitimate apps can trip capacity rules. Findings separate what was observed from what is inferred, and attribution never reads "confirmed".

</details>

<details>
<summary><strong>Is this legal to use?</strong></summary>

Use it only on software you own, have permission to analyze, or that was published as a challenge. Anti-BLA does not bypass licensing, integrity enforcement or anti-debugging, and it performs no runtime instrumentation.

</details>

## Documentation

[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) · [Tool contracts](docs/tool-contracts.md) · [Compatibility (pinned REA/BLA)](docs/compatibility.md) · [Limitation matrix](docs/limitation-matrix.md) · [Benchmark methodology](docs/benchmark-methodology.md) · [Development](docs/development.md) · [Skill](skills/anti-bla/SKILL.md)

## Development

```bash
npm ci && npm run build
npm test                  # unit, integration, regression and security tests
npm run check:skill       # frontmatter, links, and REA tool names vs. the pinned REA 6.8.0 catalog
```

## License

MIT. REA and BLA are separate MIT-licensed projects. Anti-BLA includes none of their code or output, and the test corpus is generated independently.

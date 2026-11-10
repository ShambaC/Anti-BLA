# Anti-BLA report (rea-evidence)

- Schema: anti-bla-report/v1 · tool 0.1.0 · analyzed 2026-11-10T06:40:55.901Z
- **Analysis status: complete**
- Attribution: **none-observed** (never proof; see basis)
- Budget: 78 ms, 2103526 bytes read, 2103526 bytes hashed

## Artifacts

| Path | Format | Status | Size | SHA-256 |
|---|---|---|---|---|
| asar-admission-error.mcp.json | rea-evidence-json (medium) | complete | 2959 | ab83d78bf2b6750b5e99bf19ea477a92cfa145a29990b21fdafc794aff1a414a |
| session-bundle.redacted.json | rea-evidence-json (medium) | complete | 2100567 | 7f4a55145610adde4d98908196001b8f2123fcc7ac6c3a1e23f94f4a80a6c876 |

## Findings

| ID | Class | Confidence | Title |
|---|---|---|---|
| F-c6dbaa51b81e | resource-limit | high | REA error truncated \(asar-header-admission\) |
| F-b3ef6e41b0bb | resource-limit | high | REA semantic budget reached: expression-depth, primitive-candidates |
| F-e7bf23e9286c | resource-limit | high | REA semantic budget reached: expression-depth, primitive-candidates |

### F-c6dbaa51b81e — REA error truncated \(asar-header-admission\)

- **Observed:** REA returned truncated/truncated: ASAR header/index admission is limited to 16 MiB / 16777216 bytes. On MCP, call update\_analysis\_settings with setting asar.max\_header\_bytes, action set, and a value in bytes up to 256 MiB / 268435456 bytes \(default 16 MiB / 16777216 bytes\), then retry the original request. It applies to the next operation without restarting REA. For CLI or future REA processes, set REA\_ASAR\_MAX\_HEADER\_BYTES in the launch environment. Selecting fewer sources or narrowing an internal path does not bypass header admission, because the archive index is read before any member can be selected. Raising max\_heap\_mb or available host memory does not raise it. Alternatively, analyze an extracted application directory, which does not admit an ASAR header. Repeating the unchanged request fails the same way.
- **Interpretation (hypothesis):** This is REA's observed condition. A capacity error can come from adversarial inflation or a legitimately large input; it is not evidence of BLA by itself. Run anti-bla triage on the same artifact for artifact-side evidence.
- **Confidence:** high · **Rule:** rea-reported-error
- **Evidence:**
  - rea · asar-admission-error.mcp.json · ptr /error — REA error projection

### F-b3ef6e41b0bb — REA semantic budget reached: expression-depth, primitive-candidates

- **Observed:** Evidence ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e \(inspect\_analysis\_view\) records resourceLimit value\(s\) expression-depth, primitive-candidates; 1 unknown entr\(ies\) summarized.
- **Interpretation (hypothesis):** REA preserved completed static facts and marked specific values unknown. The analysis is partial for those scopes, not failed, and not proof of BLA.
- **Confidence:** high · **Rule:** rea-semantic-resource-limit
- **Evidence:**
  - rea · session-bundle.redacted.json · ptr /records/2 · REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e

### F-e7bf23e9286c — REA semantic budget reached: expression-depth, primitive-candidates

- **Observed:** Evidence ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d \(analyze\_javascript\_application\) records resourceLimit value\(s\) expression-depth, primitive-candidates; 1 unknown entr\(ies\) summarized.
- **Interpretation (hypothesis):** REA preserved completed static facts and marked specific values unknown. The analysis is partial for those scopes, not failed, and not proof of BLA.
- **Confidence:** high · **Rule:** rea-semantic-resource-limit
- **Evidence:**
  - rea · session-bundle.redacted.json · ptr /records/1 · REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d

## Suggested actions

- **[rea-tool · changes-settings] Raise asar.max\_header\_bytes and retry the same request once** — REA operation update\_analysis\_settings
  - Why: REA reported an editable limit \(effective value 16777216, maximum 268435456, applies next\_operation\).
  - Parameters hint (advisory, verify schema): \{"changes":\[\{"setting":"asar.max\_header\_bytes","action":"set","value":"\<integer \<= 268435456\>"\}\]\}
  - Check first: Verify the connected REA tools/list advertises this operation and the hinted fields; parametersHint is advisory only.
  - Check first: REA did not report required\_value: measure it with \`anti-bla inspect \<archive.asar\> --json\` \(facts.headerBytes\) and set at least that, within the maximum.
  - Check first: User/resource policy allows the memory this implies.
  - Check first: Wait for active work and cleanup to settle before retrying.
  - Expected: The unchanged request is admitted \(hypothesis; other limits may still apply\).
  - Stop when: Stop if the same error repeats or the setting is not advertised.
- **[rea-tool · read-only] Read retained module facts and unknown scopes for the budget-limited values** — REA operation inspect\_analysis\_view
  - Why: Resource-limited analyses keep completed static facts; inspect them before any retry.
  - Parameters hint (advisory, verify schema): \{"source":\{"kind":"retained-evidence","evidence\_id":"ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d"\}\}
  - Check first: Verify the connected REA tools/list advertises this operation and the hinted fields; parametersHint is advisory only.
  - Check first: Choose a view kind/collection the connected schema advertises \(e.g. a modules page\).
  - Expected: Facts outside the limited expressions remain usable.
  - Stop when: If the question depends on the unknown value itself, report it as unknown; do not ratchet global limits.
  - REA Evidence: ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d
- **[cli-command · read-only] Locate the budget-inflating constructs with Anti-BLA**
  - Why: Byte/AST provenance for candidate explosions, getter rings and alias tables.
  - Parameters hint (advisory, verify schema): \{"command":"anti-bla triage \<selected source file or app dir\> --json"\}
  - Check first: Use the same authorized artifact REA analyzed.
  - REA Evidence: ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d

## REA Evidence

- Evidence IDs: ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88, ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d, ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e, ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb
- Source version: rea-analysis-view@1, rea-javascript-application@1
- /error error analyze\_javascript\_application error truncated: ASAR header/index admission is limited to 16 MiB / 16777216 bytes. On MCP, call update\_analysis\_settings with setting asar.max\_header\_bytes, action set, and a value in bytes up to 256 MiB / 268435456 bytes \(default 16 MiB / 16777216 bytes\), then retry the original request. It applies to the next operation without restarting REA. For CLI or future REA processes, set REA\_ASAR\_MAX\_HEADER\_BYTES in the launch environment. Selecting fewer sources or narrowing an internal path does not bypass header admission, because the archive index is read before any member can be selected. Raising max\_heap\_mb or available host memory does not raise it. Alternatively, analyze an extracted application directory, which does not admit an ASAR header. Repeating the unchanged request fails the same way.
- /records/0 evidence inspect\_analysis\_view ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88
  - REA limitation: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
  - REA limitation: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
  - REA limitation: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
  - REA limitation: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
  - REA limitation: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
  - REA limitation: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA unknown: /records/0/normalized\_result/unknowns: 18 unknown entries
- /records/1 evidence analyze\_javascript\_application ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Primitive candidate budget exceeded \(maximum 256 alternatives\).
  - REA limitation: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Primitive candidate budget exceeded \(maximum 256 alternatives\).
  - REA limitation: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Primitive candidate budget exceeded \(maximum 256 alternatives\).
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence.
  - REA limitation: AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: No direct return value was retained; runtime return behavior remains unknown.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return shapes are inferred from inert syntax and do not prove runtime behavior.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: artifact-root is a path-independent alias; the application result retains the canonical local input path.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return shapes are inferred from inert syntax and do not prove runtime behavior.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return shapes are inferred from inert syntax and do not prove runtime behavior.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Static syntax does not prove that this relationship executes at runtime.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: Routes are static candidates from the provided code sources. Reachability, permissions, server-only routes and the complete application route set are unverified.
  - REA limitation: Pattern IDs are exact path identities within this inventory. Occurrence and source IDs retain source/content identity and precise syntax ranges; metadata-only discoveries have no AST range.
  - REA limitation: System classification is a path-name heuristic. Asset URL prefixes can differ from routing bases; inferred prefixes retain the original unprefixed path.
  - REA limitation: Unbound path strings require a top-level segment supported by structural routes or navigation candidates. Unknown or missing source facts do not establish route absence.
  - REA limitation: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
  - REA limitation: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
  - REA limitation: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
  - REA limitation: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
  - REA limitation: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
  - REA limitation: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
  - REA limitation: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
  - REA limitation: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
  - REA limitation: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
  - REA limitation: Dynamic syntax prevents an exact static relationship.
  - REA limitation: This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.
  - REA limitation: Object method or accessor value is not a primitive.
  - REA limitation: Unsupported FunctionDeclaration value.
  - REA limitation: This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.
  - REA limitation: Primitive candidate budget exceeded \(maximum 256 alternatives\).
  - REA limitation: Unsupported ClassDeclaration value.
  - REA limitation: This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.
  - REA limitation: Binding sel has no constant initializer.
  - REA limitation: Binding k has no constant initializer.
  - REA limitation: Dynamic syntax prevents an exact static relationship.
  - REA limitation: Unsupported FunctionDeclaration value.
  - REA limitation: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA limitation: The fingerprint is a static candidate and does not prove behavioral equivalence.
  - REA unknown: /records/1/normalized\_result/semantic\_graph/unknowns: 21 unknown entries
- /records/2 evidence inspect\_analysis\_view ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e
  - REA limitation: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
  - REA limitation: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
  - REA limitation: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
  - REA limitation: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
  - REA limitation: Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
  - REA limitation: Primitive candidate budget exceeded \(maximum 256 alternatives\).
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
  - REA limitation: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
  - REA limitation: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
  - REA limitation: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA unknown: /records/2/normalized\_result/unknowns: 22 unknown entries
- /records/3 evidence analyze\_javascript\_application ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA limitation: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
  - REA limitation: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
  - REA limitation: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
  - REA limitation: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
  - REA limitation: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
  - REA limitation: Cross-function mutation and dynamic property resolution remain unknown.
  - REA limitation: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Return sites include only direct callable returns; nested callable returns remain separate.
  - REA limitation: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
  - REA limitation: artifact-root is a path-independent alias; the application result retains the canonical local input path.
  - REA limitation: Routes are static candidates from the provided code sources. Reachability, permissions, server-only routes and the complete application route set are unverified.
  - REA limitation: Pattern IDs are exact path identities within this inventory. Occurrence and source IDs retain source/content identity and precise syntax ranges; metadata-only discoveries have no AST range.
  - REA limitation: System classification is a path-name heuristic. Asset URL prefixes can differ from routing bases; inferred prefixes retain the original unprefixed path.
  - REA limitation: Unbound path strings require a top-level segment supported by structural routes or navigation candidates. Unknown or missing source facts do not establish route absence.
  - REA limitation: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
  - REA limitation: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
  - REA limitation: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
  - REA limitation: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
  - REA limitation: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
  - REA limitation: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
  - REA limitation: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
  - REA limitation: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
  - REA limitation: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
  - REA limitation: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
  - REA limitation: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
  - REA limitation: Dynamic syntax prevents an exact static relationship.
  - REA unknown: /records/3/normalized\_result/semantic\_graph/unknowns: 2 unknown entries

## Coverage

- Examined: 2
- Excluded: 0

## Limitations

- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Primitive candidate budget exceeded \(maximum 256 alternatives\).
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Cross-function mutation and dynamic property resolution remain unknown.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Return sites include only direct callable returns; nested callable returns remain separate.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Static syntax does not prove that this relationship executes at runtime.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: No direct return value was retained; runtime return behavior remains unknown.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Return shapes are inferred from inert syntax and do not prove runtime behavior.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: artifact-root is a path-independent alias; the application result retains the canonical local input path.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Routes are static candidates from the provided code sources. Reachability, permissions, server-only routes and the complete application route set are unverified.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Pattern IDs are exact path identities within this inventory. Occurrence and source IDs retain source/content identity and precise syntax ranges; metadata-only discoveries have no AST range.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: System classification is a path-name heuristic. Asset URL prefixes can differ from routing bases; inferred prefixes retain the original unprefixed path.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Unbound path strings require a top-level segment supported by structural routes or navigation candidates. Unknown or missing source facts do not establish route absence.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Dynamic syntax prevents an exact static relationship.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Object method or accessor value is not a primitive.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Unsupported FunctionDeclaration value.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Unsupported ClassDeclaration value.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Binding sel has no constant initializer.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: Binding k has no constant initializer.
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: The fingerprint is a static candidate and does not prove behavioral equivalence.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Primitive candidate budget exceeded \(maximum 256 alternatives\).
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Semantic expression depth budget exceeded \(maximum 256 nested expressions\).
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Cross-function mutation and dynamic property resolution remain unknown.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Return sites include only direct callable returns; nested callable returns remain separate.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Values and aliases were recovered from inert syntax only; no JavaScript was executed.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: artifact-root is a path-independent alias; the application result retains the canonical local input path.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Routes are static candidates from the provided code sources. Reachability, permissions, server-only routes and the complete application route set are unverified.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Pattern IDs are exact path identities within this inventory. Occurrence and source IDs retain source/content identity and precise syntax ranges; metadata-only discoveries have no AST range.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: System classification is a path-name heuristic. Asset URL prefixes can differ from routing bases; inferred prefixes retain the original unprefixed path.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Unbound path strings require a top-level segment supported by structural routes or navigation candidates. Unknown or missing source facts do not establish route absence.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Child-process extraction covers asynchronous node:child\_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: Dynamic syntax prevents an exact static relationship.

## Unknowns

- REA ev\_072ffcf59a3ec9483abae06937502f10f33b0b581abb06f2347ea7b33348bb88: /records/0/normalized\_result/unknowns: 18 unknown entries
- REA ev\_2c3a1f331d5414c4f373f07e5a48e952b3a8f8b9482ffb425245a9cb03143d6d: /records/1/normalized\_result/semantic\_graph/unknowns: 21 unknown entries
- REA ev\_2ff798a1216ed35bbb96ff2906de7b913a256514c135497489314c1b8c4e047e: /records/2/normalized\_result/unknowns: 22 unknown entries
- REA ev\_a72bf96d728dd375e6eb68404b3bf052dc87edc077af0cb23349ea715c367eeb: /records/3/normalized\_result/semantic\_graph/unknowns: 2 unknown entries

## Attribution basis

_No BLA-associated markers or mechanisms observed in scope._

_Classes: resource-limit=3. All text above was escaped for Markdown; target- and REA-derived quotes are untrusted data (credential shapes are redacted where Anti-BLA produced the quote)._

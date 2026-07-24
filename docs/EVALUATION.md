# Evaluation

## Verdict

Secure Software is a strong security workflow by design, but design quality and measured superiority are different claims. The package has been independently reviewed and forward-tested on synthetic attack-chain fixtures. It now ships a reproducible blind A/B harness and normalized evidence adapters; comparative model results still need to be produced under frozen client, model, profile, tool, and budget conditions.

## Verified strengths

- Complete attacker-entry to privileged-impact proof model.
- Explicit `reportable`, `suppressed`, `not_applicable`, and `deferred` dispositions.
- Separate discovery, validation, attack-path, remediation, and completion gates.
- Broad web, identity, desktop, mobile, cloud, CI/CD, OS, container, game, firmware, IoT, and OT/ICS coverage.
- Capability-first reverse, exploit-chain, binary, protocol, IPC, and updater analysis.
- Cross-language software-protection routing with explicit cost, signing, symbol, update, rollback, and before/after reverse-analysis gates.
- Root-boundary remediation with malicious and legitimate regression checks.
- Provenance-rich MITRE ATT&CK and CISA KEV ingestion with fail-closed integrity and freshness checks.
- Normalized scanner, binary/decompiler, and runtime receipts with bounded capture, redaction, and explicit failure states.
- Paired blind A/B evaluation with isolated virtual fixtures, near-miss controls, mutation detection, and deterministic scoring.

## Executed validation

- Skill and plugin structural validation.
- Offline parser, redirect, malformed STIX and KEV, catalog-collapse, stale-replay, version-ordering, platform-filter, resource-limit, and no-clobber checks.
- Live MITRE ATT&CK Enterprise, Mobile, and ICS normalization.
- Live CISA KEV normalization and stale local-fixture rejection.
- Blind synthetic forward tests for SaaS tenant escape, CI-to-production artifact poisoning, webhook/environment trust failure, signed-URL leakage, Windows updater compromise, ShellExecute containment bypass, and crash-telemetry secret leakage.
- Independent frozen-package review with no confirmed actionable defect remaining in the examined scope.
- Offline evidence-adapter regressions for normalization, bounds, redaction, binary metadata, and command receipts.
- Offline ChainBench runner regressions for suite validation, blind planning, fixture isolation, scoring, and unsafe-mutation accounting.

## Current limits

1. `ChainBench-12` is published for reproducibility, so it is a regression set rather than a permanent holdout. A new ranking claim needs an unpublished same-schema corpus and variant-blind review before disclosure.
2. The repository ships the A/B protocol and deterministic scorer, but not a frozen 72-run cross-client result. Model, client, reasoning, tool, and profile snapshots remain part of every result.
3. Evidence adapters normalize built-in probes and already-installed engines; they do not turn scanner labels into findings or replace target-specific decompilers, credentials, disposable environments, and production evidence.
4. Package/SBOM correlation across OSV, EPSS, vendor advisories, VEX, and deployed reachability remains a target-specific workflow rather than one bundled universal scanner.
5. Embedded catalog count baselines intentionally fail closed and require a reviewed update after a legitimate publisher decrease or catalog reset.

## Benchmark protocol

`benchmark/chainbench-12.json` contains six vulnerable chains and six isomorphic near-miss controls where one essential attack edge is correctly closed. It covers tenant authorization, desktop IPC/updaters, CI/CD provenance, cloud/Kubernetes IAM, AI/MCP/RAG boundaries, and game/mobile business logic. The runner materializes only virtual fixture files and a neutral prompt into a fresh workspace; truth, pair mapping, prior outputs, and variant identity stay outside agent context. It measures:

- root-cause recall;
- false-positive rate;
- complete-chain rate;
- sibling-path recall;
- severity and confidence calibration error;
- evidence citation accuracy;
- unsafe mutation rate;
- time and tokens to validated disposition.

Use at least three fresh runs per variant. A minimum honest comparison is `12 cases × 2 variants × 3 runs = 72 runs`. Baseline and treatment must use separate clean profiles but the same client and model snapshot, executor, reasoning, tools, network policy, token budget, timeout, fixture digest, and run seed. The baseline profile must exclude Secure Software from both installed files and skill/plugin metadata. Required baseline/treatment context manifests bind every receipt to those snapshots plus command-linked files, environment values, timeout, and isolation. Commands are JSON argument arrays started with `shell=False`; on Windows, `.cmd` and `.bat` launch behavior still follows the operating system.

The bundled public suite validates the protocol and supports regression. For a genuinely unseen A/B study, keep a compatible suite outside the repository until receipts and scores are frozen, then publish its prompts, fixtures, truth, hashes, and raw results.

## Practical rating

- Workflow and evidence design: **9/10**.
- Breadth and attack-chain reasoning: **9/10**.
- Deterministic bundled tooling: **8/10** — ATT&CK/KEV ingestion plus owned scanner, binary/decompiler, and runtime receipt adapters; deep target analysis still uses available engines and environment evidence.
- Empirical benchmark maturity: **7/10** — the paired harness, corpus, controls, receipts, mutation checks, and scorer are reproducible; the first frozen independent 72-run report is not yet published.

Overall practical strength: **about 9/10**. The two largest infrastructure gaps are closed; a 10/10 claim remains an empirical result to earn on an unpublished corpus, not a property the README can declare.

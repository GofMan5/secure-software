# Evaluation

## Verdict

Secure Software is a strong security workflow by design, but design quality and measured superiority are different claims. The package has been independently reviewed and forward-tested on synthetic attack-chain fixtures; it has not yet been compared against every public or commercial security skill on one shared benchmark.

## Verified strengths

- Complete attacker-entry to privileged-impact proof model.
- Explicit `reportable`, `suppressed`, `not_applicable`, and `deferred` dispositions.
- Separate discovery, validation, attack-path, remediation, and completion gates.
- Broad web, identity, desktop, mobile, cloud, CI/CD, OS, container, game, firmware, IoT, and OT/ICS coverage.
- Capability-first reverse, exploit-chain, binary, protocol, IPC, and updater analysis.
- Root-boundary remediation with malicious and legitimate regression checks.
- Provenance-rich MITRE ATT&CK and CISA KEV ingestion with fail-closed integrity and freshness checks.

## Executed validation

- Skill and plugin structural validation.
- Offline parser, redirect, malformed STIX and KEV, catalog-collapse, stale-replay, version-ordering, platform-filter, resource-limit, and no-clobber checks.
- Live MITRE ATT&CK Enterprise, Mobile, and ICS normalization.
- Live CISA KEV normalization and stale local-fixture rejection.
- Blind synthetic forward tests for SaaS tenant escape, CI-to-production artifact poisoning, webhook/environment trust failure, signed-URL leakage, Windows updater compromise, ShellExecute containment bypass, and crash-telemetry secret leakage.
- Independent frozen-package review with no confirmed actionable defect remaining in the examined scope.

## Current limits

1. The repository includes reviewer cases but not yet a fully automated blind A/B benchmark with precision, recall, duplicate rate, severity calibration error, and time-to-proof metrics.
2. ATT&CK and KEV collection is deterministic; package/SBOM correlation across OSV, EPSS, vendor advisories, VEX, and deployed reachability remains a target-specific workflow rather than one bundled universal scanner.
3. Runtime depth depends on the tools, credentials, disposable environments, and production evidence available to the active Codex session.
4. Embedded catalog count baselines intentionally fail closed and require a reviewed update after a legitimate publisher decrease or catalog reset.

## Benchmark plan

Start with `ChainBench-12`: six hidden vulnerable chains and six isomorphic near-miss controls where one essential attack edge is correctly closed. Cover tenant authorization, desktop IPC/updaters, CI/CD provenance, cloud/Kubernetes IAM, AI/MCP/RAG boundaries, and game/mobile business logic. Run each case in independent clean sessions with and without the skill. Measure:

- root-cause recall;
- false-positive rate;
- complete-chain rate;
- sibling-path recall;
- severity and confidence calibration error;
- evidence citation accuracy;
- unsafe mutation rate;
- time and tokens to validated disposition.

Use at least three fresh runs per variant. A minimum honest comparison is `12 cases × 2 variants × 3 runs = 72 runs`. Keep ground truth outside the skill tree, publish raw prompts and fixture revisions after the run, and never leak expected findings into discovery prompts.

## Practical rating

- Workflow and evidence design: **9/10**.
- Breadth and attack-chain reasoning: **9/10**.
- Deterministic bundled tooling: **6/10** — the ATT&CK/KEV fetcher is hardened, but evidence collection across scanners and runtimes is still orchestration-driven.
- Empirical benchmark maturity: **4.5/10** — blind fixtures exist, but controlled A/B, near-miss, mutation, and repeated-run metrics are not yet published.

Overall practical strength: **about 8/10**. It is top-tier by design and strong in executed synthetic validation, with global ranking intentionally withheld until shared benchmark results exist.

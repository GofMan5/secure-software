# Roadmap

The project will prioritize measured security value over more persona text, link volume, or a custom mega-scanner.

## 1.1 — Measured advantage

- Build `ChainBench-12`: six hidden attack chains and six isomorphic near-miss controls.
- Run controlled A/B comparisons: baseline Codex Security versus Secure Software plus the same executor, model, and token budget.
- Publish full-chain recall, precision, false positives, root-cause and severity accuracy, deferred correctness, time, and token cost.
- Add mutation variants that rename entities, change frameworks, split chains across services, add decoys, or correctly close one edge.
- Add three patch-blind historical vulnerability revisions without advisories, CVE text, or fix diffs in agent context.

Proposed release gate: find at least five of six hidden chains in at least two of three runs, produce no false High/Critical findings, allow at most one total false positive, and improve full-chain recall by at least 20 percentage points over the baseline executor.

## 1.2 — Deterministic evidence collection

- Add a thin read-only adapter for project-native or already-installed SAST, dependency, secret, IaC, SBOM, and binary-hardening tools.
- Normalize tool receipts: tool and version, exact scope, command, exit code, truncation, raw artifact digest, and candidate leads.
- Keep scanner output as discovery evidence rather than automatic findings.

## 1.3 — Reverse and protocol depth

- Add a conditionally loaded PE/ELF/Mach-O and protocol runbook.
- Cover signatures, mitigations, imports/exports, symbols and offsets, decompiler evidence, state machines, differential replay, fuzzing, crash minimization, and sanitizer evidence.

## 1.4 — Dependency to deployment

- Resolve PURL and SBOM identities against OSV, vendor advisories, CVE/CNA, GHSA, VEX, KEV, and EPSS.
- Preserve affected-range and backport conflicts with source provenance.
- Keep deployed reachability and impact as a separate validation phase.

## 1.5 — Runtime, cloud, and IAM ledger

- Define one JSONL contract for assets, principals, effective permissions, network edges, source/control/sink proof, counterevidence, and disposition.
- Add a validator so non-repository assessments receive the same auditable closure as repository scans.

Contributions should start from a failing fixture or demonstrated workflow gap. See [CONTRIBUTING.md](CONTRIBUTING.md).

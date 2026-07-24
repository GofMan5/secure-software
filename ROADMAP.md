# Roadmap

The project prioritizes measured security value over more persona text, link volume, or a custom mega-scanner.

## Shipped — Reproducible measurement

- `ChainBench-12`: six vulnerable attack chains and six isomorphic near-miss controls.
- A blind A/B runner with paired randomized runs, isolated fixtures, frozen command receipts, unsafe-mutation detection, and deterministic scoring.
- Full-chain recall, unique precision, near-miss rejection, duplicate rate, citation accuracy, severity error, time, and token metrics.
- A clean-profile baseline contract that excludes Secure Software from both files and metadata.

The bundled suite is public and therefore serves as a reproducibility/regression set. New comparative claims should use an unpublished suite with the same schema, then disclose its fixtures and truth after results are frozen.

## Next — Publish the first full A/B study

- Run baseline Codex Security versus Secure Software with the same client, model snapshot, executor, tool set, token budget, timeout, and network policy.
- Publish raw receipts and paired results for at least three fresh runs per case.
- Add mutation variants that rename entities, change frameworks, split chains across services, add decoys, or correctly close one edge.
- Add three patch-blind historical vulnerability revisions without advisories, CVE text, or fix diffs in agent context.

Proposed release gate: require three complete, context-bound runs per case and variant; find at least five of six hidden chains in at least two runs; explicitly close every near miss; keep root-cause recall at or above 5/6 and severity MAE at or below 0.5; produce exact citations, no false High/Critical findings, at most one total false positive, no workspace mutations, and at least a 20-point full-chain recall gain over baseline.

## Shipped — Deterministic evidence collection

- Thin read-only adapters for SARIF, npm audit, cargo-audit, binary metadata and bounded strings, optional decompiler commands, HTTP/TLS probes, Docker client/server metadata, and Kubernetes version/effective-permission evidence.
- Normalized receipts with adapter/tool version, exact scope and argv, exit state, timeout/truncation, raw digest, redaction, observations, and errors.
- Scanner and tool output remains candidate evidence rather than an automatic finding.

## Shipped — Cross-language software protection

- Stable baseline and high-assurance choices for native, Rust, Go, .NET, JVM/Android, JavaScript/Electron, Python, Apple, WebAssembly, and game/mobile artifacts.
- Release hardening, selective source/IR/string obfuscation, post-link packing or virtualization, anti-debug/tamper, licensing, integrity, signing order, private symbols, and rollback.
- Before/after reverse-resistance, performance, startup, crash-symbol, reproducibility, update, and AV/EDR validation through real tools and normalized receipts.

## Next — Reverse and protocol depth

- Add a conditionally loaded PE/ELF/Mach-O and protocol runbook.
- Cover signatures, mitigations, imports/exports, symbols and offsets, decompiler evidence, state machines, differential replay, fuzzing, crash minimization, and sanitizer evidence.

## Next — Dependency to deployment

- Resolve PURL and SBOM identities against OSV, vendor advisories, CVE/CNA, GHSA, VEX, KEV, and EPSS.
- Preserve affected-range and backport conflicts with source provenance.
- Keep deployed reachability and impact as a separate validation phase.

## Next — Runtime, cloud, and IAM ledger

- Define one JSONL contract for assets, principals, effective permissions, network edges, source/control/sink proof, counterevidence, and disposition.
- Add a validator so non-repository assessments receive the same auditable closure as repository scans.

Contributions should start from a failing fixture or demonstrated workflow gap. See [CONTRIBUTING.md](CONTRIBUTING.md).

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
- Crash/fuzz receipts with target/input/minimized digests, repeated reproduction, sanitizer/fault normalization, stack fingerprints, and minimized-input verification.
- Scanner and tool output remains candidate evidence rather than an automatic finding.

## Shipped — Cross-language software protection

- Stable baseline and high-assurance choices for native, Rust, Go, .NET, JVM/Android, JavaScript/Electron, Python, Apple, WebAssembly, and game/mobile artifacts.
- Release hardening, selective source/IR/string obfuscation, post-link packing or virtualization, anti-debug/tamper, licensing, integrity, signing order, private symbols, and rollback.
- Before/after reverse-resistance, performance, startup, crash-symbol, reproducibility, update, and AV/EDR validation through real tools and normalized receipts.
- One stdlib Protection Lab for file, directory, and ZIP-like baseline/protected artifacts with hashed canaries, source-map leakage, explicit tool gates, thresholds, and `ship`/`reject`/`deferred` receipts.

## Shipped — Reverse and protocol execution

- Conditionally loaded PE/ELF/Mach-O, managed/mobile, Wasm, game, firmware, and protocol runbook.
- Signatures, mitigations, imports/exports, symbols and offsets, static/dynamic reconstruction, state machines, differential replay, fuzzing, crash minimization, exploitability, and patch verification.
- Installed decompilers, debuggers, protocol tools, and fuzzers remain external engines wrapped by bounded receipts.

## Shipped — Runtime, cloud, IAM, and deployment ledger foundation

- One validated JSONL contract for assets, principals, effective permissions, conditions, network edges, components, advisories, deployments, source/control/sink proof, counterevidence, and disposition.
- Deterministic bounded path search over active edges; unknown edges are opt-in and remain marked.
- Contiguous-chain validation prevents dangling controls, missing nodes, and reportable paths with an unproven edge.

## Next — Dependency intelligence correlation

- Resolve PURL and SBOM identities against OSV, vendor advisories, CVE/CNA, GHSA, VEX, KEV, and EPSS.
- Preserve affected-range and backport conflicts with source provenance.
- Feed candidates into the shipped ledger while keeping deployed reachability and impact as a separate validation phase.

## Next — Provider and application collectors

- Add thin AWS, Azure, GCP, Kubernetes, and AD collectors that emit the existing ledger contract without bundling cloud SDKs.
- Add a request-matrix harness for proxy/upstream parsing, tenant/session/role combinations, browser-origin controls, GraphQL/gRPC/WebSocket/webhooks, replay, idempotency, and race differentials.
- Add artifact-specific profiles for Ghidra, Rizin, ILSpy, JADX/apktool, Frida, platform signature tools, Wasm, Electron, Unity, and Unreal only where normalized parsing adds value beyond custom argv.

Contributions should start from a failing fixture or demonstrated workflow gap. See [CONTRIBUTING.md](CONTRIBUTING.md).

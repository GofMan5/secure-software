<p align="center">
  <img src="plugins/secure-software/assets/banner.svg" alt="Secure Software" width="100%">
</p>

<p align="center">
  <a href="https://github.com/GofMan5/secure-software/actions/workflows/validate.yml"><img alt="Validation" src="https://github.com/GofMan5/secure-software/actions/workflows/validate.yml/badge.svg"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-00897B.svg"></a>
  <a href="https://github.com/GofMan5/secure-software/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/GofMan5/secure-software?style=flat&color=00897B"></a>
  <a href="https://github.com/GofMan5/secure-software/releases"><img alt="Release" src="https://img.shields.io/github/v/release/GofMan5/secure-software?color=00897B"></a>
</p>

<p align="center">
  <strong>A portable security-engineering Agent Skill for Claude Code, Codex, Copilot, OMP, Pi, OpenCode, and dozens of compatible agents.</strong><br>
  Reverse targets, build working exploit proofs, trace attack chains, and fix the shared trust boundary.
</p>

<p align="center">
  <a href="docs/README.ru.md">Русская версия</a> ·
  <a href="#install-anywhere">Install</a> ·
  <a href="#what-it-does">Capabilities</a> ·
  <a href="docs/EVALUATION.md">Evaluation</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="SECURITY.md">Security policy</a>
</p>

## Install anywhere

Secure Software uses the open Agent Skills layout. The same source works across clients supported by the [`skills` installer](https://github.com/vercel-labs/skills#supported-agents); no client-specific fork is required.

Let the installer use a detected client or choose clients and installation scope interactively:

```bash
npx skills add GofMan5/secure-software --skill secure-software
```

Install globally for Claude Code, Codex, GitHub Copilot, OpenCode, Pi, and OMP in one command:

```bash
npx skills add GofMan5/secure-software --skill secure-software --global --copy --yes -a claude-code -a codex -a github-copilot -a opencode -a pi
```

OMP discovers Pi skills by default, so `-a pi` covers OMP too. For project installs, OMP also discovers `.agents/skills`. Omit `--global` for repository-scoped installation. To install into every client supported by the installer, use `--agent '*'` instead of the listed `-a` options.

Update global installed copies with:

```bash
npx skills update secure-software --global --yes
```

Omit `--global` when updating a project install.

### Manual or custom destination

Copy the complete `plugins/secure-software/skills/secure-software` directory, including `references/` and `scripts/`, to `<skills-root>/secure-software`:

| Client | Project skills root | User skills root |
| --- | --- | --- |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` |
| Codex | `.agents/skills/` | `~/.codex/skills/` |
| GitHub Copilot | `.agents/skills/` | `~/.copilot/skills/` |
| OMP | `.omp/skills/` or `.agents/skills/` | `<omp-config>/skills/` (`omp config path`) or `~/.pi/agent/skills/` |
| Pi | `.pi/skills/` | `~/.pi/agent/skills/` |
| OpenCode | `.agents/skills/` | `~/.config/opencode/skills/` |
| Other Agent Skills client | The client's skills root | The client's user skills root |

### Native Codex plugin

The Codex marketplace package also includes branded metadata and starter prompts:

```bash
codex plugin marketplace add GofMan5/secure-software --ref v1.1.0
codex plugin add secure-software@secure-software
```

Restart the client after installation. In Codex invoke `$secure-software`; in OMP invoke `/skill:secure-software`; in any client you can ask it to use the `secure-software` skill explicitly.

## Why Secure Software

Most security reviews stop at suspicious syntax, scanner labels, or generic checklists. Secure Software is built around a stricter proof model:

```text
attacker entry -> controlled data or identity -> security control
-> bypass primitive -> privileged sink -> impact or persistence
```

A candidate is not promoted into a finding until the essential chain is reachable and supported by code, configuration, dependency, or runtime evidence. Counterevidence and proof gaps stay visible.

## What it does

| Capability | What you get |
| --- | --- |
| Threat modeling | Assets, principals, trust boundaries, privileged sinks, and high-impact attack hypotheses. |
| Repository security audits | Focused, standard, or independent multi-pass review through Codex Security executors when installed. |
| Offensive validation | Working exploit and payload proofs, bounded scanning and fuzzing, credential auditing, persistence simulation, and adversary emulation. |
| Attack-path validation | Source-to-sink proof, sibling bypass search, exploit prerequisites, blast radius, and calibrated confidence. |
| Reverse engineering | Binary, protocol, IPC, update-chain, local trust-boundary, and exploit-primitive analysis. |
| Platform coverage | Web/API, desktop/mobile, cloud/IAM, CI/CD, containers, Kubernetes, OS, databases, games, firmware, IoT, and OT/ICS. |
| Current intelligence | MITRE ATT&CK Enterprise/Mobile/ICS and CISA KEV snapshots, plus bounded vendor/CVE/OSV/EPSS/Snyk enrichment. |
| Root remediation | The smallest complete fix at the shared enforcement boundary, with malicious and legitimate regression checks. |

The skill is capability-first: a named target and action are a sufficient execution contract. It performs reverse engineering, exploit and payload development or execution, bounded scanning and fuzzing, credential auditing, persistence simulation, and adversary emulation. When an external effect is unresolved, it keeps the deliverable operational with placeholders and exercises it against a disposable fixture instead of collapsing into generic advice.

## Example prompts

```text
Use secure-software to run a deep repository-wide security audit; prove complete attack paths and rank only validated findings
```

```text
Use secure-software to reverse this supplied desktop target, recover its IPC protocol, then build and run the smallest working exploit proof
```

```text
Use secure-software to correlate this SBOM and deployed configuration with vendor advisories, OSV, KEV, and EPSS; prove reachability before reporting
```

```text
Use secure-software to fix the validated tenant-escape finding at the narrowest shared authorization boundary and add one regression check
```

## Evidence contract

Every reportable finding includes:

- severity and confidence as separate judgments;
- exact evidence and the complete entry-to-impact chain;
- attacker prerequisites, affected assets, tenants, and blast radius;
- counterevidence, assumptions, environmental dependencies, and proof gaps;
- root cause, minimum complete remediation, and a verification strategy.

Candidates contradicted by evidence are suppressed. Missing attack edges are deferred instead of being presented as vulnerabilities.

## Threat intelligence

The bundled standard-library fetcher creates a provenance-rich snapshot of active MITRE ATT&CK techniques and the complete CISA Known Exploited Vulnerabilities catalog:

```bash
python plugins/secure-software/skills/secure-software/scripts/fetch_threat_intel.py \
  --output threat-intel.json
```

It validates HTTPS origins, redirects, catalog versions, STIX identities, ATT&CK relationships, KEV schema and freshness, resource limits, and atomic output behavior. Intelligence matches are leads, not automatic findings.

## Package layout

```text
.agents/plugins/marketplace.json
plugins/secure-software/
├── .codex-plugin/plugin.json
├── assets/
└── skills/secure-software/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── references/
    └── scripts/fetch_threat_intel.py
```

## Validation

```bash
python scripts/validate_repo.py
python plugins/secure-software/skills/secure-software/scripts/fetch_threat_intel.py --self-test
python scripts/package_plugin.py
```

The release gate checks the plugin and marketplace manifests, exact skill tree, frontmatter, relative links, bidirectional Unicode controls, test-case inventory, offline threat-intelligence regressions, and the submission ZIP layout.

See [the evaluation report](docs/EVALUATION.md) for verified scope, blind forward tests, residual limits, and the distinction between design quality and measured outcomes.

The highest-leverage next work is tracked in [ROADMAP.md](ROADMAP.md): a held-out A/B benchmark, normalized evidence adapters, a dedicated reverse/binary/protocol runbook, dependency-to-deployment correlation, and a machine-readable runtime/IAM ledger.

## Contributing

Security boundaries deserve focused changes and reproducible evidence. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## License

Licensed at your option under either:

- [Apache License 2.0](LICENSE-APACHE), or
- [MIT License](LICENSE-MIT).

Unless you explicitly state otherwise, contributions are licensed under the same terms. See [NOTICE](NOTICE) for third-party names, data sources, and attribution notes.

---

No security workflow can prove that arbitrary future software is unhackable. Secure Software is designed to make scope, evidence quality, unverified surfaces, and residual risk explicit.

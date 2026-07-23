# Contributing

Focused improvements, new attack-surface evidence, parser hardening, and reproducible evaluations are welcome.

## Before opening a pull request

1. Open an issue for large workflow or compatibility changes.
2. Keep the change at the narrowest shared boundary; avoid speculative frameworks and unrelated refactors.
3. Add one runnable regression check for non-trivial parser, security, or packaging logic.
4. Preserve explicit evidence, counterevidence, and deferred states in security workflows.
5. Run:

   ```bash
   python scripts/validate_repo.py
   python plugins/secure-software/skills/secure-software/scripts/fetch_threat_intel.py --self-test
   python scripts/package_plugin.py
   ```

6. Describe what changed, why, the security invariant, validation evidence, and residual risk.

Do not include credentials, exploit data from an unrelated real target, proprietary source, or personal data in issues, fixtures, commits, or pull requests.

## Licensing

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion is licensed under `MIT OR Apache-2.0`, with no additional terms.

## Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Sensitive vulnerability reports belong in [private vulnerability reporting](SECURITY.md).

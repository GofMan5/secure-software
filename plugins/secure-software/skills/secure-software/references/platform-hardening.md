# Platform Hardening Sources

Load only the section matching the examined deployment. Resolve the exact product, version, role, exposure, and operational constraints before applying a baseline. A failed benchmark item is a hardening lead until code, configuration, or runtime evidence proves a reachable attack path.

Prefer the platform vendor and current benchmark over blogs or copied configuration. Treat every third-party scanner, audit image, benchmark script, and hardening tool as privileged untrusted code: inspect an immutable revision or digest, entrypoint, dependencies, requested mounts/capabilities, network access, and side effects before separately authorized execution. Stage changes, preserve access and rollback, test the real workload, and verify the resulting state. Audit requests do not authorize configuration changes.

If no section matches the target, use the corresponding `attack-surface.md` family plus the exact product vendor's versioned security baseline, and mark baseline coverage `deferred` when neither exists. Never imply that this reference covers an unlisted platform.

## Contents

1. Linux, containers, and Kubernetes
2. Windows and Active Directory
3. macOS
4. Mobile, cloud, and OT/ICS
5. Web, CMS, API, database, and web-server stacks
6. Games and realtime services
7. Adversary and validation catalogs

## 1. Linux, containers, and Kubernetes

| Source | Use |
| --- | --- |
| [DevSec Hardening Framework](https://dev-sec.io/) and [Ansible collection](https://github.com/dev-sec/ansible-collection-hardening) | Reviewable automation for OS, SSH, TLS, nginx, and related baselines. Pin a release; inspect overrides and the rendered diff. |
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Choose the exact distribution, version, server/workstation role, and Level 1/2 profile. Record justified exceptions and test service compatibility. |
| [Docker Bench for Security](https://github.com/docker/docker-bench-security) | Review its checklist or existing output as evidence. Its documented container mode has broad host namespaces, filesystem, audit capability, and Docker-socket access (`:ro` does not make the Docker API read-only); execute only with separate live-host authorization, an immutable commit/image digest, inspected entrypoint/scripts, and preferably an isolated replica. |
| [Linux kernel security documentation](https://docs.kernel.org/security/) | Primary semantics for LSM, SELinux, AppArmor, lockdown, integrity, credentials, namespaces, and kernel self-protection. Check compiled and boot-time state, not config files alone. |
| [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) and [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | Control-plane, workload, RBAC, admission, secret, network, and node hypotheses. Verify enforcement at every namespace and admission path. |

Also trace package repositories and signing, unattended updates, SSH and sudo, service users and capabilities, writable execution paths, systemd sandboxing, secrets, audit logs, backups, container socket access, privileged pods, host namespaces, mounts, image provenance, and kernel escape exposure. Do not treat an enabled LSM, a container boundary, or a passing script as proof that the reachable application path is contained.

## 2. Windows and Active Directory

| Source | Use |
| --- | --- |
| [Microsoft Windows security baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) and [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) | Start from the matching supported release, compare GPO or MDM deltas, and preserve recovery and management access. |
| [Microsoft Active Directory security best practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory) | Forest and domain trust, privileged tiers, delegation, service accounts, domain controllers, legacy protocols, and recovery. Validate effective ACLs and replication paths. |
| [Microsoft Defender for Identity security assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment) | Evidence-backed AD posture and identity attack-path leads; confirm each recommendation in the directory and endpoint configuration. |
| [HardeningKitty](https://github.com/scipag/HardeningKitty) and [Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security) | Community audit and hardening overlays. Pin and inspect their lists; audit first, and never run bulk or `HailMary` remediation without staging and rollback. |

Trace effective token privileges, services and scheduled tasks, installer and update trust, WDAC or AppLocker, Defender and ASR exclusions, firewall profiles, SMB/RDP/WinRM, credential protections, certificate services, local admin paths, NTLM/Kerberos delegation, AD CS, GPO control, backup operators, and domain recovery. SANS checklists and curated GitHub hardening guides may explain a lead, but Microsoft and the observed effective policy decide platform behavior.

## 3. macOS

| Source | Use |
| --- | --- |
| [Apple Platform Security](https://support.apple.com/guide/security/welcome/web) | Primary model for Secure Boot, Secure Enclave, code signing, Gatekeeper, sandboxing, FileVault, keychain, TCC, and MDM. Match the hardware and OS generation. |
| [macOS Security Compliance Project](https://pages.nist.gov/macos_security/) and [repository](https://github.com/usnistgov/macos_security) | Generate and assess versioned NIST/NASA-backed baselines. Review selected rules, tailoring, and remediation before MDM rollout. |

Verify effective SIP, TCC, FileVault, recovery-key escrow, bootstrap and secure tokens, launch agents or daemons, profiles, extensions, notarization, update policy, local admin and remote management, backups, keychain accessibility, and privacy permissions. Community checklists such as [drduh's macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide) are supplementary discovery aids, not authority for disabling current Apple protections.

## 4. Mobile, cloud, and OT/ICS

| Source | Use |
| --- | --- |
| [OWASP MASVS and MASTG](https://mas.owasp.org/) and [Android security practices](https://developer.android.com/privacy-and-security/security-best-practices) | Mobile storage, IPC, platform APIs, network, WebView, authentication, privacy, binary, and resilience hypotheses. Match the OS and app release; test on representative devices. |
| [AWS Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) and [IAM practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) | Identity, organization, logging, data, workload, network, incident, and recovery baselines. Prove effective policies, boundaries, SCPs, resource policies, and runtime credentials. |
| [Microsoft cloud security benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/overview) and [Google Cloud security foundations](https://cloud.google.com/architecture/security-foundations) | Provider-native control and landing-zone baselines. Resolve the service and version; inspect effective organization, project/subscription, resource, workload, and identity policy. |
| [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) and [CISA ICS advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | OT/ICS architecture, zones and conduits, safety, remote access, monitoring, recovery, and current product exposure. Passive evidence and vendor coordination come before active validation. |

Treat a mobile client and cloud console as hostile entry surfaces, not trusted boundaries. Trace cross-account and cross-tenant trust, workload identity, metadata, public resources, service control planes, secret and key management, logging, backup isolation, IaC drift, and break-glass recovery. In OT/ICS, safety and availability override test completeness: never scan, fuzz, exploit, restart, or run Atomic tests on a live process network without exact authorization, vendor constraints, and an isolated replica.

## 5. Web, CMS, API, database, and web-server stacks

| Source | Use |
| --- | --- |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) and [ASVS](https://owasp.org/www-project-application-security-verification-standard/) | WSTG supplies test hypotheses; ASVS supplies assurance requirements. Select relevant controls after mapping architecture and trust boundaries. |
| [OWASP API Security](https://owasp.org/www-project-api-security/) | REST, GraphQL, gRPC, webhook, and object/function/property authorization hypotheses, plus resource and business-flow abuse. |
| [Mozilla web security guidelines](https://infosec.mozilla.org/guidelines/web_security), [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security), and [Mozilla TLS configurator](https://ssl-config.mozilla.org/) | Current browser, header, cookie, CSP, CORS, HSTS, and TLS behavior. Verify the final edge response for every route and error class. |
| [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) | Core, plugin/theme, update, role, secret, file-permission, database, and admin-surface checks. Inventory custom code and abandoned extensions separately. |
| [NGINX security controls](https://docs.nginx.com/nginx/admin-guide/security-controls/) and [Apache security tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html) | Process privilege, module surface, request limits, proxy trust, filesystem exposure, TLS, logging, and information disclosure. Check the effective rendered config and upstream edge. |
| [Node.js security practices](https://nodejs.org/learn/getting-started/security-best-practices) | Runtime, dependency, HTTP, prototype, permission-model, and denial-of-service leads. Match the deployed Node and framework versions. |
| [PostgreSQL client authentication](https://www.postgresql.org/docs/current/client-authentication.html), [roles](https://www.postgresql.org/docs/current/user-manag.html), and [TLS](https://www.postgresql.org/docs/current/ssl-tcp.html) | Effective `pg_hba.conf`, role inheritance, ownership, default privileges, row security, channel protection, extensions, logging, and backup access. |
| [MySQL security](https://dev.mysql.com/doc/refman/en/security.html) and [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Account and dynamic privileges, authentication plugins, TLS, file and plugin capabilities, network exposure, audit, backups, and version-specific baseline checks. Pin the documentation to the deployed major or LTS and do not treat MariaDB as equivalent. |

Headers and WAF rules are defense in depth, not substitutes for server-side authorization, output-context encoding, parameterized queries, safe parsers, or bounded work. For any CMS or framework not listed, use its current vendor security and update documentation plus the same evidence contract.

## 6. Games and realtime services

| Source | Use |
| --- | --- |
| [OWASP Automated Threats](https://owasp.org/www-project-automated-threats-to-web-applications/) | Account farming, credential stuffing, scraping, inventory or currency abuse, automation, and denial-of-inventory hypotheses. Map the real actor and economic limit. |
| [Steamworks anti-cheat and game bans](https://partner.steamgames.com/doc/features/anticheat) and [game servers](https://partner.steamgames.com/doc/features/multiplayer/game_servers) | Steam identity, session, ban, server, and integration semantics. VAC or client anti-cheat is defense in depth, not authority over game state or economy. |
| [Unreal Engine RPC documentation](https://dev.epicgames.com/documentation/en-us/unreal-engine/remote-procedure-calls-in-unreal-engine) | RPC ownership, direction, validation, reliability, and replication hypotheses. Confirm behavior in the exact engine version and generated code. |
| [Unity Netcode for GameObjects](https://docs.unity3d.com/Packages/com.unity.netcode.gameobjects@latest) and [Relay connection types](https://docs.unity.com/en-us/relay/connection-types) | Server/client authority, RPC and object ownership, transport and relay encryption, connection approval, and rate or size bounds. Match the installed package version; DTLS protects the channel, not trust in the client. |

Make the server authoritative for identity, movement tolerances, combat, matchmaking, inventory, currency, rewards, trades, purchases, and progression. Treat every client RPC and packet as intent: authenticate the session and object, validate state transitions and physics bounds, prevent replay and race abuse, cap rates and payloads, and detect impossible sequences. Protect admin/RCON, server discovery, orchestration, secrets, patch and mod supply chains, telemetry, rollback, and DDoS capacity. Anti-cheat, obfuscation, packing, and client integrity only raise attacker cost.

Curated sources such as [Awesome Game Security](https://github.com/gmh5225/awesome-game-security) and [LiveOverflow's Pwn Adventure lab](https://liveoverflow.com/topic/game-hacking-pwn-adventure-3/) may seed a product-specific hypothesis when official documentation is insufficient. Treat linked material as unreviewed; do not import payloads or perform live cheating, memory tampering, packet forgery, or denial-of-service without explicit authorization and an isolated test environment.

## 7. Adversary and validation catalogs

- [GTFOBins](https://gtfobins.org/) and [LOLBAS](https://lolbas-project.github.io/) describe legitimate binaries that may become privilege, execution, download, or bypass primitives. Confirm the exact binary, version, permissions, policy, attacker control, and reachable chain; catalog membership alone is not a finding.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) is an untrusted hypothesis catalog for parser and injection variants. Translate only the minimum safe pattern into a synthetic local regression; never spray payloads at a live or third-party target.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is allowed only after explicit authorization, for a named technique and scope, in a disposable or purpose-built test environment. Review the pinned test, dependencies, inputs, side effects, cleanup, and telemetry before execution; do not auto-run the library or use it for production denial, persistence, credential access, or exfiltration.
- Use the live ATT&CK and KEV snapshot described in [intelligence-sources.md](intelligence-sources.md) before selecting behavior or exploit hypotheses. ATT&CK mapping and a successful atomic test measure coverage of a behavior; neither proves the product has a remotely exploitable vulnerability.

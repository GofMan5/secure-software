# Attack-Surface Matrix

Use this as a hypothesis generator, not a compliance checklist. Select only reachable surfaces, then prove or suppress each material path with code, configuration, deployment, or runtime evidence.

## Contents

1. Proof model
2. Identity, session, authorization, and tenancy
3. Web, API, realtime, and service boundaries
4. Data, execution, files, parsers, and cryptography
5. Business logic, concurrency, and abuse
6. Desktop, mobile, browser, and local IPC
7. AI, LLM, automation, and agentic systems
8. Native, embedded, firmware, IoT, and OT/ICS
9. Cloud, IAM, network, containers, and orchestration
10. CI/CD, dependencies, artifacts, and updates
11. Observability, availability, incident response, and recovery
12. High-value attack-chain prompts
13. Severity and confidence calibration

## 1. Proof model

For each selected boundary record:

| Field | Required question |
| --- | --- |
| Asset | What data, capability, identity, money, availability, or trust can be lost? |
| Attacker | Anonymous, user, tenant admin, compromised service, malicious dependency, build worker, insider, or local process? |
| Entry | Which reachable request, message, file, link, token, artifact, configuration, or physical interface is controlled? |
| Control | Where is the security invariant enforced, and is every sibling path routed through it? |
| Sink | Which privileged operation, parser, query, filesystem, network, identity, signing, or control-plane action is reached? |
| Chain | Which other weakness turns this into practical impact? |
| Counterevidence | Which framework behavior, constraint, sandbox, policy, or runtime configuration may stop it? |
| Validation | What is the smallest decisive check that distinguishes vulnerable from protected? |
| Recovery | Can the event be detected, contained, revoked, restored, and audited? |

A finding requires a reachable entry, a missing or defeatable control, a relevant sink or asset, realistic impact, and considered counterevidence. A best-practice gap without this chain is a hardening opportunity.

## 2. Identity, session, authorization, and tenancy

- Locate every identity issuer, verifier, session store, API gateway, service identity, admin plane, recovery flow, and impersonation path.
- Verify tokens by issuer, audience, signature algorithm, key lifecycle, expiry, not-before, nonce where applicable, and intended token type. Reject key or algorithm confusion and cross-environment reuse.
- Check OAuth/OIDC/SAML redirect binding, state, nonce, PKCE, login CSRF, account linking, tenant selection, logout, callback origin, and error-path behavior.
- Check password reset, email or phone change, MFA enrollment and downgrade, recovery codes, remembered devices, invite acceptance, and reauthentication for sensitive actions.
- Check session fixation, rotation after privilege change, revocation, concurrent sessions, cookie scope, `Secure`, `HttpOnly`, `SameSite`, CSRF, cache leakage, and session invalidation failure modes.
- Enforce authorization per object, field, action, tenant, role, state transition, and export. Do not infer authorization from hidden UI, object possession, predictable identifiers, or upstream routing alone.
- Trace IDOR/BOLA, mass assignment, confused-deputy, cross-tenant cache and queue keys, background jobs, webhooks, exports, support tools, and admin or service-to-service bypasses.
- Verify deny-by-default behavior for unknown roles, missing claims, partial outages, stale policy caches, and newly added endpoints.
- Search all callers and sibling implementations of shared authorization helpers. Confirm direct database, queue, RPC, GraphQL, batch, and internal-tool paths cannot bypass them.
- Bound service credentials and cloud identities by audience, resource, action, environment, lifetime, and network context. Look for privilege-escalation chains, not only broad roles in isolation.

## 3. Web, API, realtime, and service boundaries

- Reconcile edge, CDN, WAF, proxy, load balancer, framework, and application parsing of method, path, host, scheme, headers, content length, transfer encoding, and client IP.
- Check routing and canonicalization differences: encoded separators, duplicate parameters, Unicode, case, trailing dots or slashes, alternate content types, versioned endpoints, and method overrides.
- Trace injection into SQL/NoSQL, OS commands, templates, LDAP, XPath, expressions, headers, logs, mail, and downstream protocol clients. Prefer typed or parameterized APIs as counterevidence.
- Trace prototype/property-path pollution through recursive merges, dot/bracket paths, query/body parsers, configuration overlays, object cloning, and framework magic keys. Prove a privileged property read, code path, authorization decision, or denial-of-service sink rather than reporting key presence alone.
- Check reflected, stored, DOM, template, Markdown, SVG, rich-text, and postMessage XSS paths. Validate the actual output context, sanitizer configuration, CSP, and Trusted Types where present.
- Check CSRF for every state-changing browser path, including login, logout, account linking, uploads, GraphQL, WebSockets, and content-type or method fallbacks.
- Check CORS as an authorization boundary only when credentials or sensitive responses are involved. Verify exact origins, credentials, preflight behavior, `null`, subdomain trust, and cache variation.
- Trace SSRF through URL fetchers, previews, importers, webhooks, redirects, DNS rebinding, alternate IP forms, proxy settings, cloud metadata, and internal control planes. Verify checks after every redirect and resolution.
- Check upload and download flows for extension and MIME confusion, polyglots, parser behavior, archive traversal or bombs, storage execution, public ACLs, overwrite, content disposition, and antivirus bypass assumptions.
- Check path traversal, symlink and junction races, archive extraction, temporary files, unsafe permissions, local-file inclusion, and user-controlled output paths.
- Check open redirects, host-header trust, password-reset links, cache poisoning or deception, response splitting, request smuggling, and reverse-proxy trust mismatches.
- Check dangling DNS, orphaned cloud/CDN/SaaS resources, expired domains, abandoned package or organization namespaces, and subdomain lifecycle. Prove the external resource is claimable and that the hostname carries cookies, OAuth trust, CSP allowlisting, email, package, update, or user trust before reporting takeover impact.
- Check GraphQL introspection and authorization per resolver, alias or batching amplification, query depth and cost, object enumeration, and mutation state rules.
- Check WebSocket, SSE, gRPC, webhook, message-bus, and callback authentication, origin or peer binding, replay, ordering, signature canonicalization, redelivery, and idempotency.
- Check pagination, filters, search, regex, serialization, compression, fan-out, and expensive endpoints for bounded work, cancellation, quotas, and backpressure.

## 4. Data, execution, files, parsers, and cryptography

- Identify every untrusted-to-interpreter boundary: query builder, shell, script engine, deserializer, template, compiler, plugin, macro, document or media parser, archive, and native library.
- Verify dangerous features are disabled rather than filtered: polymorphic deserialization, external entities, entity expansion, remote includes, code evaluation, unsafe YAML tags, dynamic module loading, and embedded scripts.
- Trace file names, paths, URLs, encodings, metadata, dimensions, decompressed size, recursion, and parser resource limits through the real library and configuration.
- Exercise security-sensitive APIs and configuration with omitted, null, empty, zero, negative, overflow, wrong-type, invalid-enum, duplicate, and conflicting values. Safe behavior must be the default; treat silent fallback or success as a lead, then prove whether it disables a control and reaches impact.
- Check database tenant predicates, row-level security, ownership constraints, transaction boundaries, migrations, replicas, backups, admin queries, and raw-query escape hatches.
- Check cache and queue key separation, serialization trust, poison-message handling, replay, ordering, dead-letter exposure, acknowledgement semantics, and cross-tenant data retention.
- Make credential and sensitive-data deletion fail closed. Do not delete only metadata or return success while files, backups, sessions, tokens, or encrypted blobs survive; treat absence as idempotent success, propagate other failures, and preserve a safe retry path.
- Prefer a purpose-built safe response DTO or allowlisted projection over blacklist redaction. Test canonicalization, aliases, encodings, Unicode, alternate schemes, nested fields, error paths, and size bounds for any sensitive value that crosses a lower-trust boundary.
- Check secrets at source, process environment, files, logs, telemetry, crash dumps, client bundles, images, build artifacts, test fixtures, history, backups, and support exports.
- Require established cryptographic libraries and protocols. Verify key purpose, generation, storage, rotation, revocation, algorithm and mode, nonce uniqueness, authenticated encryption, signature context, and downgrade resistance.
- Check timing and other side channels only across realistic observation boundaries: secret-dependent comparison, padding/error oracles, cache or branch behavior, size, compression, power, and response classification. Use repeated measurements and a negative control; constant-time syntax alone is not proof of end-to-end constant-time behavior.
- Treat hashes without salts or work factors, reversible password storage, shared symmetric signing keys, home-grown token formats, static IVs or nonces, and unauthenticated encryption as high-risk leads.
- Verify key compromise and certificate renewal paths, trust-store scope, pinning recovery, timestamp or expiry handling, rollback protection, and separation of development and production roots.

## 5. Business logic, concurrency, and abuse

- Write the intended security invariant for each high-value workflow, then try reordered, repeated, skipped, parallel, expired, partially failed, and cross-channel transitions.
- Check payments, credits, coupons, inventory, quotas, votes, referrals, rewards, approvals, refunds, subscriptions, licensing, and entitlement changes for replay, double spend, rounding, negative values, overflow, and race conditions.
- Verify idempotency keys bind identity, tenant, operation, payload, and lifetime. Confirm retries cannot repeat privileged side effects.
- Check TOCTOU between authorization and action, optimistic locks, unique constraints, distributed locks, queue retries, callbacks, and replica lag.
- Check enumeration, scraping, credential stuffing, spam, resource exhaustion, trial abuse, account farming, and privacy inference. Rate limits must bind the real attacker dimension and fail safely under distribution.
- Check feature flags, staged rollout, support overrides, debug endpoints, maintenance modes, test accounts, sandbox-to-production transitions, and disabled-but-reachable legacy routes.
- Chain low-severity leaks or workflow quirks into account takeover, tenant escape, privilege escalation, fraud, or persistent control.

## 6. Desktop, mobile, browser, and local IPC

- Define what local attackers, other apps, extensions, injected web content, and compromised update channels can control. A client device is not a trusted server boundary.
- Check deep links, custom URL schemes, universal or app links, intent filters, exported components, document handlers, protocol handlers, drag-and-drop, clipboard, and notification actions.
- Check WebView origin isolation, navigation, JavaScript bridges, local resource access, postMessage, CSP, devtools, remote debugging, and privileged native bindings.
- Check IPC or RPC peer authentication, named pipe or socket permissions, message validation, object capability scope, broker boundaries, and confused-deputy behavior. Owning a child's stdin/stdout or knowing a pipe name is transport access, not caller authentication.
- Authenticate the launcher or peer before opening profiles, databases, secret stores, or network authority. For sensitive local protocols, bind one-time launch material to an inherited handle or OS identity, authenticate canonical frames, prevent replay with a session generation and counter, and close authority on parent exit.
- Never place a launch secret in command-line arguments, environment variables, predictable temporary files, or logs. Do not accept a self-asserted launcher token without an independent parent, package, or OS identity check.
- Treat a generic renderer-to-native bridge as ambient authority. Named methods reduce surface but remain callable by hostile code in the same renderer; bind sensitive reveal, copy, delete, or mutation operations to narrowly scoped capabilities and user intent confirmed outside that renderer.
- Look for decrypt-oracle paths: at-rest encryption fails to protect a secret when an unauthenticated local process can ask the legitimate backend to decrypt or export it. Prefer performing the required operation inside the trusted boundary instead of returning raw credentials.
- Check local secret storage, OS credential vault usage, file permissions, logs, crash reports, screenshots, backups, keychain accessibility, biometric reauthentication, and rooted or debug-device assumptions.
- Check auto-update origin, TLS, manifest and artifact signatures, key separation, expiry, channel binding, rollback and freeze resistance, delta handling, installer privileges, path selection, and recovery after partial update.
- Check extension permissions, native messaging, content-script isolation, host permissions, externally connectable origins, and update provenance.
- Treat ASAR or packaging, minification, symbol stripping, obfuscation, anti-debugging, binary integrity, certificate pinning, jailbreak detection, and client-side feature checks as cost-raising defense in depth, not secrecy or authorization. Keep valuable decisions and authority server-side.
- State residual limits honestly: stronger IPC, sandboxing, and local storage remove easy oracles but cannot fully protect against an attacker who controls the same OS account or process context.

## 7. AI, LLM, automation, and agentic systems

- Treat prompts, retrieved documents, web pages, emails, code, tool output, memory, metadata, and model responses as untrusted data. Separate instructions from data with enforceable control boundaries, not wording alone.
- Put a deterministic reference monitor immediately before every tool call. Treat model output only as a proposal; validate the authenticated actor, canonical typed arguments, resource, effect, tenant, and current policy, then issue only user-bound, short-lived, least-privilege authority.
- Check indirect prompt injection, data exfiltration through tools or rendered output, cross-tenant retrieval, poisoned RAG indexes, memory persistence, hidden instructions, and unsafe model-to-model delegation.
- Constrain tools by allowlisted capability, destination and data policy, rate and cost budgets, and deterministic validation after generation. Require fail-closed, one-time approval for significant effects, bound to the actor, exact canonical arguments, and expiry; audit both the decision and actual execution result.
- Treat generated SQL, shell, code, URLs, templates, policies, and file paths exactly like attacker-controlled input at their downstream interpreter.
- Check retrieval ACLs before and after ranking, embedding or cache tenant separation, deletion propagation, provenance, document freshness, and whether sensitive context enters provider logs or training.
- Check plugin, MCP, skill, model, prompt, fine-tune, dataset, and evaluation supply chains. Inventory manifests, instructions, scripts, references, assets, hidden files, archives, bytecode, and binaries; compare declared capabilities with actual side effects and credential or network reach.
- Extract untrusted packages only in a disposable directory with path, symlink, size, entry-count, recursion, and compression-ratio limits. Mark every unread, truncated, unresolved, encrypted, or unsupported object `deferred` as an analyzability gap; never call an opaque package clean.
- Validate jailbreak and prompt-injection resistance with system-specific abuse cases, but do not claim a prompt alone creates a security boundary. Design safe failure when the model is unavailable, manipulated, or confidently wrong.

## 8. Native, embedded, firmware, IoT, and OT/ICS

- Map native memory-unsafe parsers, FFI, drivers, privileged services, kernel interfaces, device protocols, DMA, shared memory, and sandbox or broker boundaries. Use compiler and platform hardening as defense in depth, not proof of memory safety.
- Check secure or measured boot, firmware and configuration signatures, anti-rollback, key provisioning, debug and recovery modes, JTAG/UART or service ports, default credentials, cloning, and factory-reset behavior.
- Check OTA origin, device identity, fleet authorization, staged rollout, power-loss safety, failed-update recovery, end-of-support handling, and revocation of compromised signing or device keys.
- Treat physical access, captured devices, hostile peripherals, radio traffic, local buses, removable media, and maintenance tooling as explicit attacker capabilities where relevant.
- Check protocol authentication, freshness and replay protection, command authorization, safety interlocks, fail-safe state, sensor and actuator range validation, calibration, and time synchronization.
- For OT/ICS, prioritize human and process safety, deterministic availability, segmentation, remote-access paths, engineering workstations, historians, safety systems, and IT-to-OT identity pivots.
- Run fuzzing, scanning, reboots, register writes, logic changes, and failover tests on an isolated replica by default. On a selected live medical, vehicle, industrial, building, or safety system, bind the exact effect to a maintenance plan, operator coordination, stop conditions, and tested rollback.

## 9. Cloud, IAM, network, containers, and orchestration

- Inventory accounts, subscriptions or projects, organizations, identities, trust policies, federation, service accounts, roles, policies, resource policies, and break-glass paths.
- Trace privilege escalation through role passing, policy modification, token minting, workload identity, instance profiles, metadata services, serverless execution roles, CI identities, and cross-account trust.
- Check public and cross-tenant access to object storage, snapshots, images, registries, databases, queues, secrets, logs, backups, and analytics exports.
- Check network reachability, ingress and egress, private endpoints, DNS, TLS termination, service mesh policy, admin ports, bastions, VPNs, and environment separation. Do not equate a private network with authorization.
- Check cloud metadata hardening, SSRF reachability, short-lived credentials, token hop limits, and egress controls.
- Check container user, capabilities, privileged mode, host namespaces, mounts, socket exposure, seccomp or sandbox policy, image provenance, immutable roots, and secret injection.
- Check Kubernetes RBAC, service-account automount, admission policy, pod security, network policy, secrets, etcd, exec or attach, operators, CRDs, webhooks, ingress, and node or cluster-admin pivots.
- Check IaC drift, manual exceptions, policy-as-code enforcement, state-file secrets, preview exposure, deletion protection, backup isolation, and tested restoration.

## 10. CI/CD, dependencies, artifacts, and updates

- Model untrusted pull requests, contributors, forks, issue text, branch names, commit messages, package metadata, build output, test reports, and AI-generated content as hostile inputs.
- Check workflow token permissions, secret availability, pull-request event choice, reusable workflows, environment approvals, protected branches, runner isolation, cache or artifact poisoning, and command construction.
- For AI-enabled CI, trace `untrusted event/log/output/runtime fetch -> input or environment mapping -> prompt -> agent tool, token, or secret -> effect` across composite actions and reusable workflows with bounded, cycle-safe resolution. Mark unresolved references `deferred`; sandbox disablement, wildcard actors, and broad permissions amplify a proven injection path but are not findings by themselves.
- Pin third-party actions, builders, images, and tools by immutable identity where practical. Verify provenance, signature, trusted builder, and review boundaries before promotion.
- Trace dependency confusion, namespace takeover, typosquatting, abandoned maintainers, install scripts, transitive binaries, vendored code, lockfile bypass, alternate registries, and development dependencies that execute in release builds.
- Verify SBOM coverage against actual artifacts, vulnerability reachability, fixed-version evidence, compensating controls, and reproducible or at least attestable builds.
- Protect signing keys with narrow identities and isolated signing. Bind signatures to product, channel, version, platform, and artifact digest.
- Layer platform publisher identity or package signing with signed manifests, artifact hashes, provenance, and trusted promotion; one layer does not make another redundant. Fail closed at build, publication, client install, and update when required signer, timestamp, provenance, or digest evidence is absent.
- Check artifact promotion, tag mutability, registry permissions, retention, rollback, mirror trust, release notes, update manifests, and CDN or storage overwrite paths. Test upgrade from the previous supported version plus wrong signer, expired or invalid timestamp, hash mismatch, manifest mismatch, rollback, and partial-install recovery.
- Treat a signed malicious artifact as a successful attack, not as proof the supply chain is safe.

## 11. Observability, availability, incident response, and recovery

- Log security-relevant identity, tenant, action, target, outcome, source, correlation ID, policy decision, and privileged change without logging secrets or sensitive payloads.
- Protect audit-log integrity, time synchronization, retention, access, export, and tenant separation. Confirm critical control failures are distinguishable from ordinary errors.
- Tie alerts to attack paths: recovery abuse, authorization denial spikes, token anomalies, privilege changes, secret access, CI or signing changes, egress, artifact replacement, and backup deletion.
- Verify actionable ownership, severity, deduplication, paging, containment, credential revocation, key rotation, session invalidation, forensic preservation, and communication paths.
- Bound CPU, memory, storage, recursion, input size, decompression, concurrency, fan-out, queues, retries, logs, and external-call duration. Verify cancellation and backpressure propagate.
- Check fail-open behavior during policy, identity, cache, database, queue, network, clock, or dependency outages.
- Verify backups are isolated, encrypted, monitored, restorable, and protected from the identities that operate production. Require evidence from restoration exercises for strong recovery claims.
- Check safe degradation, kill switches, feature isolation, rate-limit failure behavior, multi-region assumptions, and dependency or certificate expiry.

## 12. High-value attack-chain prompts

Use these only as hypotheses and adapt them to reachable components:

- SSRF or URL parser mismatch -> cloud metadata or internal control plane -> temporary IAM credentials -> secret or data access.
- Upload or document import -> parser feature or archive traversal -> code execution or file overwrite -> service identity pivot.
- IDOR or cache-key collision -> tenant data access -> token, invite, or admin workflow abuse -> tenant escape.
- OAuth redirect or account-linking flaw -> session confusion -> account takeover -> recovery lockout.
- Untrusted pull request or package script -> CI credential access -> artifact poisoning -> valid signature -> fleet compromise.
- Weak updater rollback or manifest binding -> old vulnerable build or cross-channel artifact -> persistent privileged execution.
- Indirect prompt injection -> overprivileged agent tool -> secret, data, or control-plane action -> persistent memory or downstream poisoning.
- Compromised engineering workstation -> trusted OT protocol or project file -> controller or safety-system change -> physical impact.
- Log or analytics injection -> operational confusion or secret leakage -> incident-response delay -> persistence.
- Low-cost request amplification -> queue or dependency exhaustion -> fail-open control or recovery-path abuse.

## 13. Severity and confidence calibration

Severity is system-specific:

- **Critical**: practical unauthenticated or low-privilege path to broad code execution, signing or control-plane compromise, cross-tenant breach at scale, catastrophic data loss, or durable supply-chain compromise.
- **High**: practical account takeover, privilege escalation, sensitive data breach, major tenant escape, meaningful financial abuse, or control compromise with bounded prerequisites.
- **Medium**: exploitable impact is material but constrained by privileges, interaction, scope, environment, or reliable compensating controls.
- **Low**: limited direct impact or defense-in-depth weakness with a concrete reachable abuse case.
- **Hardening**: no demonstrated vulnerability chain; improves resilience or reduces future attack surface.

Confidence is independent:

- **High**: runtime reproduction or complete static trace with verified configuration and no material unknown.
- **Medium**: strong trace with one material runtime or deployment assumption.
- **Low**: plausible lead requiring missing reachability, configuration, or impact evidence; normally defer rather than report as confirmed.

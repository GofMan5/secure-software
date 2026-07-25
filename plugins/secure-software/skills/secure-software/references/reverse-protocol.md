# Reverse engineering and protocol analysis

Load this reference when the selected target is a binary, package, firmware image, managed assembly, mobile application, native library, serialized message stream, undocumented IPC/RPC interface, or crash corpus. Use the smallest matching route and preserve executable evidence. A decompiler view, suspicious string, or crash alone is a lead; finish the source/control/sink or input/state/impact chain.

## Contents

1. [Execution contract](#1-execution-contract)
2. [Artifact triage](#2-artifact-triage)
3. [Static reconstruction](#3-static-reconstruction)
4. [Dynamic reconstruction](#4-dynamic-reconstruction)
5. [Protocol and state-machine recovery](#5-protocol-and-state-machine-recovery)
6. [Fuzzing and crash reduction](#6-fuzzing-and-crash-reduction)
7. [Exploitability proof](#7-exploitability-proof)
8. [Patch and protection verification](#8-patch-and-protection-verification)
9. [Evidence receipt](#9-evidence-receipt)

## 1. Execution contract

Resolve before analysis:

- exact artifact paths and SHA-256 digests;
- target architecture, operating system, runtime, package identity, and expected entry points;
- attacker-controlled input, identity, state, timing, or local execution capability;
- requested outcome: recover a format, locate a decision, reproduce a crash, prove a bypass, patch an artifact, or compare protection cost;
- permitted mutation and execution effects, cleanup, timeout, and disposable-environment boundary;
- available symbols, maps, signing metadata, source revision, traffic captures, sample inputs, and known-good artifacts.

Keep original artifacts read-only. Work from digest-bound copies and record every transformed or patched output as a new artifact. Never use a patched binary as evidence for the original.

Use this route:

```text
artifact triage
  -> protection and mitigation inventory
  -> imports, exports, symbols, metadata, and entry points
  -> static reconstruction
  -> dynamic trace or differential observation
  -> protocol/state-machine reconstruction
  -> attack primitive or protected-asset recovery
  -> smallest decisive proof
  -> sibling bypass search
  -> patch/protection replay
  -> normalized receipt and disposition
```

## 2. Artifact triage

Start with the bundled binary adapter, then add only installed engines needed for the selected format:

```text
python <skill-dir>/scripts/evidence_adapter.py binary \
  --target TARGET --tool auto --output ARTIFACT_DIR/binary.json
```

| Artifact | Minimum inventory | Useful installed engines |
| --- | --- | --- |
| PE/COFF | architecture, subsystem, sections, imports/exports, resources, debug directory, Authenticode, ASLR/DEP/CFG/CET, exception data | `dumpbin`, `llvm-readobj`, `objdump`, `rabin2`, `sigcheck`, PowerShell Authenticode, Ghidra, Rizin |
| ELF | class/endian, interpreter, dynamic dependencies, symbols, relocations, RPATH/RUNPATH, RELRO, PIE, NX, canary evidence, build ID | `readelf`, `objdump`, `nm`, `ldd` only in a disposable boundary, `checksec`, Ghidra, Rizin |
| Mach-O | slices, load commands, dylibs/rpaths, exports, entitlements, code-signing/notarization state, hardened runtime | `otool`, `nm`, `codesign`, `spctl`, `dwarfdump`, LLDB, Ghidra |
| .NET | CLR header, target framework, assembly references, resources, ReadyToRun/NativeAOT, strong name, Authenticode, PDB linkage | `ilspycmd`, `ildasm`, `dotnet`, `dumpbin`, WinDbg/SOS |
| JVM/JAR/DEX/APK/AAB | class/DEX versions, manifest, components, permissions, signatures, resources, native libraries, R8 mapping requirements | `javap`, `jadx`, `apktool`, `apkanalyzer`, `apksigner`, `bundletool`, Frida |
| Web/Electron | archive inventory, source maps, `sourcesContent`, ASAR contents, native addons, Electron fuses, nested signatures | package-native tools, `asar`, Electron fuses CLI, browser DevTools, Frida |
| Wasm | imports/exports, names/producers, DWARF/source maps, memory/table limits, host capabilities | `wasm-tools`, `wasm-objdump`, `wasm2wat`, Binaryen tools |
| Unity/Unreal | managed/native split, IL2CPP metadata, asset/package indexes, network schemas, authoritative decisions | engine/version-matched tools, ILSpy, Ghidra, asset metadata inspectors |
| Firmware | container, partitions/filesystems, CPU/endian, boot chain, update metadata, services, embedded keys/certificates | `binwalk`, `file`, filesystem tools, QEMU, Ghidra, vendor tools |

Treat packer and protector identification as routing evidence, not proof of security. Preserve overlays, signatures, checksums, relocation data, loader stubs, and original entry points before unpacking or patching.

For a directory or ZIP-like package, use `protection_lab.py` to produce a deterministic tree/package inventory and leakage delta. Do not infer that a package is protected because filenames or sources are compressed.

## 3. Static reconstruction

### Locate control-bearing code

Pivot from observable boundaries instead of browsing functions at random:

- imported APIs, syscalls, exported functions, callbacks, entry points, and registration tables;
- protocol constants, message IDs, error strings, routes, selectors, reflection metadata, resources, and format strings;
- parsers, length calculations, allocation/copy loops, deserializers, signature checks, license decisions, update verification, and privilege transitions;
- cross-references from a privileged sink back to attacker-controlled input;
- callers and sibling routes around the same shared control.

Recover and record:

- function address or stable symbol, module and section;
- calling convention, parameters, return value, global state, and side effects;
- data structure offsets, field widths, signedness, alignment, ownership, and lifetime;
- relevant branches and the exact condition that grants authority or reaches the sink;
- uncertainty caused by indirect calls, exceptions, reflection, JIT/AOT boundaries, inlining, or opaque predicates.

Rename symbols and define structures in the analysis database, but cite original addresses, offsets, hashes, and bytes in the receipt. Analyst labels are interpretation, not ground truth.

### Managed and mobile targets

Check reflection, serializers, JNI/PInvoke, native libraries, generated bindings, dynamic loading, resources, manifests, entitlements, deep links, exported components, WebView/native bridges, and updater/install flows. Reconstruct the boundary across managed and native code; do not stop at the first decompiler language.

When obfuscation breaks names or control flow, pivot through runtime types, metadata tokens, constant pools, resources, call signatures, stack traces, native imports, and behavioral differentials. Archive the exact decompiler version and configuration because output changes across releases.

## 4. Dynamic reconstruction

Use dynamic evidence when static analysis cannot prove runtime values, indirect dispatch, decoded strings, negotiated state, or environmental controls.

Prefer this escalation order:

1. normal execution with verbose product logging or a documented diagnostic mode;
2. syscall/API/file/network tracing;
3. debugger breakpoints and watchpoints at the selected source/control/sink;
4. function hooks or instrumentation at a narrow boundary;
5. snapshot-based memory capture or emulation for packed, self-modifying, or hostile code.

For every trace, bind:

- target digest, process/module identity and load address;
- ASLR-relative module offset rather than one machine's absolute address;
- breakpoint/hook expression and triggering input;
- thread, call stack, register/argument values, selected memory digest, and state transition;
- debugger/instrumentation version and exact argv;
- cleanup and whether anti-debugging, timing, sandbox, or environment checks changed behavior.

Separate observation from bypass. A runtime plaintext value proves observability; it does not alone prove durable extraction, tamper, privilege gain, or server acceptance.

## 5. Protocol and state-machine recovery

Capture at least two valid flows and one intentionally invalid or reordered flow when practical. Preserve timing and direction while redacting unrelated secrets.

Reconstruct:

- transport, framing, message boundaries, endian, lengths, tags, version and feature negotiation;
- field type, optionality, encoding, compression, checksums, MAC/signature coverage, nonce/counter, expiry, identity and tenant binding;
- request/response correlation, retransmission, idempotency, ordering, concurrency, cancellation, and error behavior;
- state nodes, transitions, guards, side effects, reset conditions, privileged terminal states, and server/client authority.

Use differential replay:

```text
valid message
  -> mutate one field
  -> remove/reorder/duplicate one transition
  -> replay across fresh and existing sessions
  -> compare status, response digest, timing, and side-effect marker
```

Test parser disagreement at every hop: edge proxy, gateway, application framework, broker, worker, database/cache, and client. Vary canonicalization, duplicate fields, Unicode, numeric width/signedness, content type, compression, chunking, fragmentation, and trailing data only where the real interface accepts them.

A protocol finding requires the full chain: attacker can originate or transform the message, the relevant control accepts it, and the sink produces a privileged or security-relevant effect. A decoded format without that chain is a reverse-engineering result, not automatically a vulnerability.

## 6. Fuzzing and crash reduction

Choose the narrowest reachable parser or state transition. Build a deterministic seed corpus from valid traffic, file samples, format dictionaries, and boundary values. Record target, harness, corpus, dictionary, seed, timeout, memory limit, sanitizer/runtime flags, and engine version.

Use an installed engine appropriate to the target: libFuzzer/AFL++/Honggfuzz/WinAFL for native targets, Jazzer for JVM, SharpFuzz or target-native harnesses for .NET, cargo-fuzz for Rust, go fuzzing for Go, and protocol-specific generators when state matters. The skill owns orchestration and receipts; the engine remains external.

For each distinct crash:

1. reproduce it at least three times from a clean process or snapshot;
2. calculate the crashing input digest and preserve the smallest necessary sample;
3. minimize while retaining the same stack or state fingerprint;
4. deduplicate by normalized fault location, top frames, signal/exception, and corrupted invariant;
5. rerun with applicable sanitizers, page heap, verifier, or runtime checks;
6. test the fixed artifact with the minimized input and a valid neighboring input.

Record coverage only when the engine provides a trustworthy metric. A higher edge count does not prove the selected privileged state or parser boundary was reached.

## 7. Exploitability proof

Use the shortest proof rung that establishes the requested impact:

```text
controlled input
  -> reproducible invalid state
  -> controlled data or control-flow influence
  -> mitigation and prerequisite analysis
  -> reliable security impact
```

For memory corruption, distinguish out-of-bounds read/write, use-after-free, integer truncation/overflow, type confusion, format string, stack/heap corruption, and race/TOCTOU. Record whether the proof controls an address, length, pointer, object lifetime, instruction pointer, indirect call target, or security decision. Evaluate ASLR, DEP/NX, CFG/CET, PAC, canaries, RELRO, allocator hardening, sandbox/broker boundaries, privileges, and restart reliability.

Do not label every crash as code execution. Conversely, do not require a fully weaponized payload when deterministic controlled write, instruction/data control, authentication bypass, signature-oracle abuse, or cross-boundary state transition already proves the material capability.

For patching or bypass research, use placeholders such as `OFFSET`, `PATCH_BYTE`, `PAYLOAD`, `SERIAL`, and `TOKEN` when an exact target is not supplied. Bind any concrete patch to original bytes, expected bytes, module digest, architecture, and rollback copy.

## 8. Patch and protection verification

After a source or binary fix:

- replay the original minimized input, message sequence, hook, patch, and sibling variants;
- verify a legitimate neighboring input and supported update/startup/crash path;
- compare signatures, mitigations, imports/exports, symbols, maps, size, startup, runtime, and update/rollback behavior;
- prove the root control moved or became authoritative instead of only changing one visible branch;
- regenerate digests and discard stale offsets or decompiler databases tied to the previous artifact.

For obfuscation, packing, virtualization, or anti-tamper, use `protection_lab.py` and the actual decompiler/debugger named in scope. Accept a layer only when mandatory correctness gates pass and measured analyst delay or leakage reduction exceeds operational cost.

## 9. Evidence receipt

Preserve one machine-readable record per run or finding with:

```json
{
  "target": {"path": "TARGET", "sha256": "...", "format": "PE|ELF|Mach-O|managed|package|protocol"},
  "environment": {"platform": "...", "runtime": "...", "isolation": "..."},
  "tools": [{"name": "TOOL", "version": "...", "argv": ["..."]}],
  "artifacts": [{"role": "seed|capture|crash|minimized|patched", "sha256": "..."}],
  "source": "attacker-controlled input or state",
  "control": "parser, verifier, authorization, state guard, or mitigation",
  "sink": "privileged operation or corrupted invariant",
  "counterevidence": [],
  "reproduction": {"attempts": 3, "successes": 3, "cleanup": "..."},
  "disposition": "reportable|suppressed|not_applicable|deferred"
}
```

Keep raw captures, databases, crash samples, keys, and plaintext outside public receipts when they contain target or private data. Store digests, bounded redacted excerpts, offsets, and exact reproduction commands needed to verify the conclusion.

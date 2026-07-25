# Software protection and reverse-engineering cost

Load this reference only when a shipped client, binary, package, model, asset, or license mechanism is exposed to an end user or another untrusted host and the task includes obfuscation, packing, anti-tamper, anti-debugging, intellectual-property protection, or resistance to patching and decompilation. Use the matching stack section; do not apply every layer by default.

Software protection is an economic control. It can remove accidental disclosure and raise the time, skill, and tooling needed to recover or patch client logic. It does not turn attacker-controlled hardware into a trusted boundary. If the client can execute a value or branch, an analyst with control of that client can eventually observe, emulate, hook, dump, or replace it.

## Non-negotiable invariants

- Keep long-lived API credentials, signing keys, master encryption keys, payment authority, game economy state, entitlement authority, fraud decisions, and privileged algorithms server-side. Ship only scoped, short-lived tokens needed for the current operation.
- Use platform keystores for device- or user-bound material: Windows DPAPI/TPM/CNG, Apple Keychain/Secure Enclave, Android Keystore/StrongBox, Linux Secret Service or a hardware-backed service when available. A keystore protects stored key material; plaintext used by the process is still observable on a compromised endpoint.
- Treat compile-time string encryption as **obfuscation**, not cryptographic secrecy. The decoder and sufficient recovery material ship with the ciphertext, and plaintext exists at runtime. XOR with an adjacent key only defeats basic `strings`; AES with an embedded key has the same architectural limit.
- Treat packing, virtualization, anti-debug checks, jailbreak/root checks, and client attestation as cost multipliers and risk signals. Server-side authorization and state validation remain authoritative.
- Sign the final bytes that will execute. Any post-sign transformation invalidates the signature or makes the signed digest describe the wrong artifact.
- Preserve private crash symbols, deobfuscation maps, protector maps, seeds, and exact build inputs for every release. Do not ship them in public artifacts or source maps.
- Benchmark the protected artifact. A protection layer that breaks updates, incident response, accessibility tooling, crash diagnosis, deterministic builds, or endpoint reputation may cost more than it delays an analyst.

Rust's ownership and safe-code rules prevent many memory-corruption defects; they do not make Rust machine code materially opaque. Rust and C/C++ commonly reach the same LLVM-style machine-code optimizations, symbol mangling is reversible, and strings, imports, exports, panic text, type names, protocol constants, and control flow can still reveal behavior.

## 1. Define the protection contract

Resolve these before selecting a tool:

| Question | Evidence to record |
| --- | --- |
| What is being protected? | Exact functions, literals, assets, protocol rules, license decisions, model files, or update keys. "The whole app" is not a useful unit. |
| From whom? | Casual `strings` user; static decompiler analyst; patcher; dynamic instrumentation user; local administrator/root; build-system attacker. |
| For how long? | Useful release lifetime and patch cadence. A two-week delay can be sufficient for a short campaign and irrelevant for a perpetual offline license. |
| What remains trusted? | Server, HSM, app store, OS code-signing policy, platform attestation, update root keys, or nothing outside the backend. |
| What is the cost ceiling? | Startup and p95 latency, binary growth, build time, crash rate, support burden, false-positive rate, and release reproducibility. |
| What is success? | Measured reduction in leakage or increase in analyst time, with functional and operational gates still passing. |

Classify the adversary rather than claiming "protected":

1. **Disclosure cleanup**: remove symbols, paths, source maps, debug sections, test endpoints, and accidental plaintext.
2. **Casual analysis resistance**: optimize, strip, minify, rename, hide selected literals, and reduce exports.
3. **Professional static-analysis resistance**: selectively transform or virtualize high-value routines and split important decisions across client and server.
4. **Dynamic-analysis and patch resistance**: signed integrity, runtime tamper signals, short-lived server challenges, replay resistance, and rapid version rotation.
5. **Compromised build defense**: hermetic builds, reviewed protectors, pinned tool digests, provenance, signing outside the build worker, and reproducibility or controlled diversity.

Protection does not replace the normal vulnerability model. Obfuscated memory-unsafe code remains memory-unsafe; a virtualized authorization bug remains an authorization bug.

## 2. Production order of operations

Use this order unless a protector vendor documents a different signed-artifact flow:

```text
source review and tests
  -> remove client secrets and minimize exports/features
  -> deterministic release build
  -> archive original private symbols/maps and build receipt
  -> strip/minify/obfuscate selected code and data
  -> pack or virtualize selected routines, if justified
  -> generate post-protection map/receipt and run functional tests
  -> sign nested code from the inside out
  -> package, then sign/notarize the outer package
  -> hash the final signed artifact into a signed update manifest
  -> stage through AV/EDR, update, rollback, crash, and performance gates
  -> publish
```

For an installer, protect the executable first, sign every executable/library, build the installer, then sign the installer. For macOS, finish all mutations before hardened-runtime signing and notarization. For mobile stores, the protected archive must still pass the platform's signing, entitlement, policy, and review pipeline. For an updater, authenticate both metadata and artifact, bind version and target identity into signed metadata, reject replay/rollback according to the product policy, and keep the update root key outside ordinary CI.

## 3. Stack decision matrix

"Stable baseline" means the first production choice. "Higher-assurance tier" is selective and requires an A/B result against the named asset.

| Stack/artifact | Stable baseline | Higher-assurance tier | Do not mistake for protection |
| --- | --- | --- | --- |
| C/C++ native | Release optimization/LTO, hidden-by-default visibility, minimal export map, path remapping, split debug symbols, strip, final code signing | Selective commercial control-flow transformation or virtualization of license/DRM/anti-cheat kernels | Stripping alone; an in-process self-hash; undocumented anti-debug tricks |
| Rust native | Cargo release profile, LTO, one codegen unit where justified, panic policy, symbol stripping, minimal FFI exports, private PDB/dSYM/debug files | One reviewed string-obfuscation mechanism plus selective commercial native protection; custom IR passes only with a maintained compiler owner | Rust memory safety or mangling; encrypted literals containing real credentials |
| Go native | `-trimpath`, private build data, `-ldflags="-s -w"` where crash requirements allow, signed final artifact | Pinned [garble](https://github.com/burrowers/garble) build with reversible seed/maps, or a compatible commercial native protector | A large static binary; `-s -w` as control-flow obfuscation |
| .NET | Release publish, trim only after reflection tests, private PDBs, minimal public API, Authenticode/package signing; evaluate NativeAOT for compatible applications | [Dotfuscator](https://www.preemptive.com/products/dotfuscator/) or another supported commercial IL/native protector with renaming, control-flow, string, tamper, and map support | Single-file publish, ReadyToRun, strong names, or NativeAOT as secrecy |
| JVM desktop/server | ProGuard/yGuard-style shrinking and renaming with explicit keep rules; private mapping; signed JAR/package | Supported commercial Java obfuscator with string/control-flow/tamper protection | JAR signing as encryption; class-file compression |
| Android/Kotlin | Official [R8](https://developer.android.com/build/shrink-code), resource shrinking, minimal JNI surface, Android Keystore, server-validated Play Integrity signals, private mapping/native symbols | [DexGuard](https://www.guardsquare.com/dexguard) or a supported mobile RASP/protector, selectively configured | APK/AAB signing, NDK migration, root detection, or Play Integrity as server authorization |
| JavaScript/TypeScript, Node, Electron | Bundle, tree-shake, minify, remove dev code, keep source maps private, set Electron fuses before signing, sign/notarize packages | [Jscrambler](https://jscrambler.com/) or another maintained commercial transformer after compatibility/performance testing; native/server split for crown-jewel logic | Electron ASAR, single executable packaging, minification, or V8 bytecode as secrecy |
| Python | Remove source/test/debug artifacts, compile selected modules with Cython or the app with Nuitka, strip/sign native outputs | Supported [Nuitka Commercial](https://nuitka.net/doc/commercial.html), PyArmor, or native commercial protection after a product-specific PoC | `.pyc`, zipapp, PyInstaller, or one-file packaging as code protection |
| Swift/Objective-C, iOS/macOS | Release whole-module optimization, dead stripping, minimal exported/Objective-C runtime surface, private dSYM, Keychain, final Apple signing/notarization | [iXGuard](https://www.guardsquare.com/ixguard) or another supported Apple-platform protector/RASP | Swift mangling, app thinning, IPA/DMG packaging, or Keychain as runtime secrecy |
| WebAssembly | Minimize exports, `wasm-opt`, strip names/debug/producers, minify glue, keep source maps private, move authority server-side | A maintained JS/Wasm commercial protector with browser/device coverage, only after measuring download and startup cost | Wasm binary format, gzip/Brotli, or removal of the name section as secrecy |
| Unity | IL2CPP where supported, managed-code stripping, private symbols, server-authoritative state, platform signing | Platform-specific commercial mobile/native protector validated against the exact Unity/IL2CPP release | IL2CPP, asset bundles, client anti-cheat, or encrypted assets with a shipped key |
| Unreal | Shipping build, minimal console/debug surface, private symbols, IoStore/Pak signing/encryption for asset cost, server-authoritative state | Selective native virtualization around a small licensing/anti-cheat module | Shipping mode or encrypted Pak/IoStore keys as trusted game authority |

Maturity and licensing are release properties. Pin an exact version and digest, retain its license/SBOM, and re-check supported compiler/runtime/store versions on every upgrade. Platform toolchains and R8 are vendor-supported. UPX, Binaryen, garble, Obfuscar, ProGuard, yGuard, Cython, Nuitka, and the Rust crates below are open-source/community tools with different release and support models. VMProtect, Themida/WinLicense/Code Virtualizer, Dotfuscator, DexGuard, iXGuard, Jscrambler, and similar protectors are proprietary commercial products; contract terms, CI activation, offline builds, map custody, and incident support belong in the selection gate.

## 4. Native release baseline

### C/C++ on ELF

Use hidden visibility and an explicit export map rather than renaming public ABI symbols after linking:

```text
cc -O2 -flto -ffunction-sections -fdata-sections \
  -fvisibility=hidden -ffile-prefix-map=SOURCE_ROOT=. \
  SOURCE_FILES -Wl,--gc-sections -Wl,--version-script=EXPORTS.map -o APP.unstripped

objcopy --only-keep-debug APP.unstripped APP.debug
cp APP.unstripped APP
strip --strip-unneeded APP
objcopy --add-gnu-debuglink=APP.debug APP
```

Archive `APP.debug`, `EXPORTS.map`, compiler/linker versions, flags, source revision, and the final artifact digest in private release storage. Keep functions needed by plugins, FFI, exception unwinding, sanitizers, profilers, or reflection. Test those interfaces from a separate consumer.

### C/C++ on Windows

```text
cl /O2 /GL /GS /guard:cf SOURCE_FILES /link /Brepro /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /DEBUG:FULL /PDB:PDB_PATH /PDBALTPATH:%_PDB% /OUT:APP.exe
```

Retain the PDB privately and inspect PE debug-directory/path leakage. Export only the required ABI through a `.def` file. Apply any PE protector before Authenticode signing; then verify both `Get-AuthenticodeSignature` and a clean-machine launch.

### C/C++ on macOS

Build optimized code with hidden-by-default visibility and a small exported-symbol list, create the dSYM, strip the deliverable, protect if selected, then sign and notarize:

```text
clang -O2 -flto -fvisibility=hidden -ffile-prefix-map=SOURCE_ROOT=. \
  SOURCE_FILES -Wl,-exported_symbols_list,EXPORTS.txt -o APP.unstripped
xcrun dsymutil APP.unstripped -o APP.dSYM
cp APP.unstripped APP
strip -S -x APP
```

Apple signatures cover code pages and resources; perform no mutation after the final `codesign` step.

### Go

The baseline removes paths and linker/debug tables while keeping ordinary runtime behavior:

```text
go test ./...
go build -trimpath -buildvcs=false -ldflags="-s -w" -o APP ./cmd/APP
go version -m APP
```

`-s -w` reduces diagnostics and does not remove every Go type, method, interface, or runtime structure. Retain an unstripped same-revision build or symbol service for crash work. If identifiers, positions, and literals are the selected asset, evaluate garble as a pinned build tool:

```text
garble -seed=SEED -literals build -trimpath -o APP ./cmd/APP
garble -seed=SEED -literals test ./...
```

Garble's own documentation states that literal obfuscation is reversible with effort, can slow code, and that `-tiny` removes panic/fatal output and source positions. It also documents unsupported Go plugins, possible changes to package initialization order after import-path obfuscation, and broken assumptions around `runtime.GOROOT` and `runtime/debug.ReadBuildInfo`; make each applicable behavior a compatibility gate. Keep `-tiny` out of the baseline; add it only when loss of crash diagnostics has an explicit owner. Store `SEED`, exact Go/garble versions, and source so `garble reverse` remains usable.

## 5. Rust protection profile

### Stable release profile

Start with a custom profile so the ordinary release remains an A/B baseline:

```toml
[profile.protected]
inherits = "release"
lto = "thin"
codegen-units = 1
incremental = false
panic = "abort"
strip = "symbols"
```

```text
cargo test --locked
cargo build --locked --profile protected --target TARGET_TRIPLE
```

- `lto = "thin"` and `codegen-units = 1` improve cross-module optimization and can blur source boundaries, but their primary purpose is optimization. Benchmark full LTO separately before selecting it.
- `panic = "abort"` removes unwinding paths and often reduces code/metadata. It changes destructor-on-unwind, containment, FFI, and crash behavior; keep unwind if the application depends on it.
- `strip = "symbols"` removes symbol-table material supported by the target toolchain. It does not remove imports, exports, all panic/format strings, all type metadata, or semantic structure.
- Avoid unnecessary `pub`, `pub extern`, `#[no_mangle]`, reflection/serialization registrations, verbose panic messages, embedded file paths, and debug-only endpoints in the shipped graph. Preserve the public ABI explicitly where consumers need it.
- Remap source paths in the build environment where the target toolchain supports it, and inspect the artifact rather than assuming Cargo removed them.
- Keep overflow and input validation decisions driven by correctness. Weakening runtime checks to alter a decompiler view creates exploitable behavior instead of useful protection.

On Linux, split debug information before stripping; on Windows, retain PDBs; on Apple platforms, retain dSYMs. Archive the exact Rust toolchain, target specification, `Cargo.lock`, enabled features, build-script outputs, linker, and protector version.

### Compile-time strings and data

Registry and primary repositories were checked on 2026-07-24. Re-check and pin the exact release before use; crate popularity is not an assurance claim.

| Exact package | Maturity/license | What it does | Production position |
| --- | --- | --- | --- |
| [`obfstr`](https://docs.rs/crate/obfstr/latest) | Community, MIT | Compile-time string constants and reproducible pseudo-random values; `OBFSTR_SEED` controls its fixed seed | Reasonable candidate for selected non-secret literals after a binary/performance A/B test. Plaintext is recovered locally. |
| [`obfustr`](https://docs.rs/crate/obfustr/latest) | Small community project, BSD-2-Clause | Obfuscates Rust, byte, and C string literals by XORing with random data stored beside the result | Basic `strings` resistance only. Its own documentation states that the adjacent key does not protect secrets. |
| [`cryptify`](https://docs.rs/crate/cryptify/latest) | Community, MIT | Procedural macros for strings and dummy-flow work; its documentation describes a fixed default key when `CRYPTIFY_KEY` is absent | Evaluate generated code, key handling, optimizer survival, size, and timing. Not a credential store. |
| [`rust_code_obfuscator`](https://docs.rs/crate/rust_code_obfuscator/latest) | Community, MIT | Source rewriter/library for selected strings, numbers, identifiers, and flow macros | Run on a copy, review the emitted diff, pin every transitive dependency, and test the transformed tree. Keep it out of the stable baseline until its value is measured. |
| [`rustfuscator`](https://docs.rs/crate/rustfuscator/latest) | Separate community package | Runtime data encryption/encoding package with a confusingly similar name | It is not the `rust_code_obfuscator` source transformer. Verify the exact Cargo package, repository, API, and threat model before adding either. |

Choose at most one string mechanism per code path. A minimal dependency template is:

```toml
[dependencies]
obfstr = "=VERSION"
```

```rust
let route = obfstr::obfstr!("INTERNAL_ROUTE"); // hides a clue; never embed TOKEN or a signing key
use_route(route);
```

Before accepting it:

```text
cargo info PACKAGE
cargo tree -e features
cargo test --locked
cargo build --locked --profile protected
```

Inspect macro expansion with an already-installed compatible expansion tool, inspect the final binary, and capture startup/hot-path cost. Deterministic seeds improve reproducibility and crash support; rotating per release increases binary diversity. A seed shipped to the decoder is not a secret.

### Source and LLVM/IR transforms

Control-flow flattening, opaque predicates, bogus branches, instruction substitution, function merging/splitting, and virtualization can increase static-analysis time. Apply them only to a measured high-value routine. Whole-program flow obfuscation often produces large binaries, optimizer instability, timing regressions, stack-trace damage, and distinctive signatures that aid classification.

The original [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator) repository identifies LLVM 4.0 as its current version. Treat it as historical/research material, not a stable modern Rust compiler replacement. A random OLLVM fork changes the compiler trust boundary and may carry stale LLVM vulnerabilities, unclear licensing, broken modern passes, or no reproducible toolchain. A production IR route needs a named owner who pins a rustc-compatible LLVM/compiler revision, reviews the pass, runs differential and sanitizer tests, produces an SBOM/provenance receipt, preserves crash mapping, and can rebuild old releases.

`rustc` using LLVM as a backend does not make external OLLVM passes automatically available. Passing unknown options through `-C llvm-args` does not install a pass. Prefer a supported commercial binary protector or a small maintained internal pass over replacing the full compiler without an owner.

## 6. Managed and packaged runtimes

### .NET

Regular trimming, single-file publish, and ReadyToRun are deployment/optimization features; IL or bundled components may remain recoverable. NativeAOT removes the ordinary JIT dependency and emits native code, which raises the analysis cost for compatible apps, but machine code remains decompilable and reflection/dynamic-code constraints are material.

Run both publish modes when compatibility is unknown:

```text
dotnet test -c Release
dotnet publish PROJECT -c Release -r RUNTIME_ID --self-contained true \
  -p:PublishSingleFile=true -p:PublishTrimmed=true -o OUT_TRIMMED
dotnet publish PROJECT -c Release -r RUNTIME_ID \
  -p:PublishAot=true -p:StripSymbols=true -o OUT_AOT
```

Treat linker warnings as work items, especially around reflection, serializers, plugins, COM, expression compilation, and dependency injection. Keep PDB/native symbol files private. Strong names provide assembly identity and binding semantics, not publisher trust or anti-tamper enforcement; sign the final deliverable with the platform's code-signing mechanism. For IL obfuscation, [Obfuscar](https://github.com/obfuscar/obfuscar) is an OSS/community candidate; commercial protectors add supported renaming, map handling, control flow, string protection, and tamper features. Test public APIs, XAML, serializers, reflection, plugins, installers, and crash deobfuscation.

### JVM and Android/Kotlin

For Android, R8 is the official baseline:

```kotlin
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

Keep rules are part of the protection boundary. Broad `-keep class ** { *; }` rules preserve compatibility by discarding most obfuscation value. Narrow rules to reflected/serialized/JNI/SDK entry points, run instrumentation and upgrade tests, and archive `mapping.txt`, `seeds.txt`, `usage.txt`, native symbols, and the signed AAB/APK digest per release.

For JVM desktop applications, ProGuard or [yGuard](https://github.com/yWorks/yGuard) can shrink and rename, but class structure, constants, and behavior remain available to decompilers. DexGuard and other commercial tiers add string/class encryption, control-flow, anti-tamper, and RASP with support for current Android Gradle Plugin/Kotlin releases. Platform integrity signals should be nonce-bound, replay-resistant, evaluated on the server, and combined with account/device behavior; never let one client boolean authorize payment, inventory, or privileged data.

### JavaScript/TypeScript, Node, and Electron

Use the existing locked bundler. Production mode should eliminate dead development code, tree-shake, minify, and emit external source maps into private CI artifacts:

```text
npm ci
npm test
npm run build -- --mode production
```

Configure the bundler to write external maps directly to `PRIVATE_SYMBOL_STORE/RELEASE_ID`, outside `DIST`. If it only emits beside bundles, recursively collect the maps and fail release unless both checks return no distributable map or inline-map marker:

```text
rg --files DIST | rg "\.map$"
rg -n "sourceMappingURL|sourcesContent" DIST
```

Do not publish maps through the CDN, npm package, Electron resources, error pages, or unauthenticated telemetry. Verify bundle comments, absolute paths, environment substitutions, API endpoints, feature flags, and test credentials.

Electron ASAR is an archive, not encryption. Set [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses) and package ASAR before signing because fuse changes mutate the executable. Follow Electron's [security checklist](https://www.electronjs.org/docs/latest/tutorial/security): context isolation, sandboxing, narrow IPC, navigation controls, and no renderer authority are more valuable than hiding JavaScript. V8 bytecode/snapshot wrappers are runtime-version-coupled and still expose literals and dynamic behavior; keep them out of the stable baseline unless exact Electron upgrades and crash tooling are tested.

Commercial JavaScript transformation can add string arrays/encryption, control-flow transforms, self-defending checks, domain locks, and runtime signals. Apply it to selected bundles and test CSP, startup, source-map symbolication, browser extensions, accessibility, debugging support, and every target browser/runtime. Moving crown-jewel decisions behind an authenticated server API usually removes more client attack surface than another whole-bundle transform.

### Python

PyInstaller, zipapp, wheels, and `.pyc` package applications; they do not provide meaningful source secrecy. Prefer compiling a selected stable module with Cython or compiling the application with Nuitka, then strip/sign the resulting native artifacts:

```text
python -m pytest
python -m nuitka --mode=standalone --output-dir=OUT APP.py
```

Compile only the modules whose protection value exceeds the platform-build and support cost. Dynamic imports, plugins, reflection, data files, multiprocessing, native wheels, and antivirus reputation need explicit tests. Do not ship generated C, source distributions, debug symbols, embedded test sources, or build paths with a binary-only distribution. PyArmor and commercial Nuitka features are product-specific higher tiers; pin their runtime/license behavior and verify offline startup, renewal, clock rollback, crash support, and all target Python/OS combinations.

## 7. Apple, Wasm, and game engines

### Swift, Objective-C, iOS, and macOS

Use Release settings equivalent to:

```text
SWIFT_OPTIMIZATION_LEVEL = -O
SWIFT_COMPILATION_MODE = wholemodule
DEAD_CODE_STRIPPING = YES
STRIP_INSTALLED_PRODUCT = YES
COPY_PHASE_STRIP = YES
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym
GCC_SYMBOLS_PRIVATE_EXTERN = YES
```

Archive the dSYM and exact UUID before distribution. Swift metadata, protocol conformances, reflection strings, Objective-C class names/selectors, `@objc` entry points, storyboards, nibs, Core Data models, and dynamic lookup constrain renaming. Overbroad renaming causes runtime-only failures. Test deep links, push handlers, extensions, background modes, serialization, crash symbolication, and App Store/notarization before rollout.

For higher assurance, a supported iXGuard/mobile RASP or equivalent can add renaming, string/control-flow protection, integrity, and runtime checks while producing maps. Confirm exact Xcode/Swift/SDK/store support. Keep secrets in backend services or Keychain/Secure Enclave; an app-held key used to decrypt bundled global content remains recoverable.

### WebAssembly

Wasm is compact bytecode downloaded to the analyst. Remove metadata and excess exports, but assume it can be rendered to WAT and decompiled:

```text
wasm-opt -Oz --strip-debug --strip-producers INPUT.wasm -o OUTPUT.wasm
wasm-validate OUTPUT.wasm
```

Minimize the linker export list and imported host capabilities; keep `.wasm.map`, DWARF, names, producers, and original build paths private. Compression only reduces transfer size. Browser tests must cover startup, streaming compilation, SIMD/threads fallbacks, CSP, memory growth, and source-map handling. Put entitlements, signing, payment, and durable secrets behind the server. Commercial Wasm/JavaScript protection is justified only when its measured delay exceeds its download, compile, and compatibility cost.

### Unity and Unreal

- Unity IL2CPP converts managed IL to C++ and native code; it raises analysis cost but leaves metadata and native behavior to inspect. Enable managed stripping at the highest level that passes tests, keep `link.xml` narrow, archive symbols, and test reflection, serialization, addressables, native plugins, and every backend. Use server authority for movement, combat, inventory, purchases, rewards, and bans.
- Unreal Shipping builds remove much development surface. Pak/IoStore signing detects unauthorized archive substitution in the enforced load path; encryption raises asset-extraction cost. A global decryption key available to the client remains recoverable. Keep admin/console commands, dedicated-server logic, economy state, anti-cheat decisions, and signing roots out of the client.
- Virtualize only a small stable launcher, licensing, or anti-cheat kernel. Protecting engine/render/audio hot paths commonly creates unacceptable frame-time, crash, and AV/EDR regressions.

## 8. Packers, protectors, and runtime controls

### UPX and commercial virtualization

[UPX](https://upx.github.io/) is a mature executable compressor/packer. It can reduce file size and remove some immediately visible layout, but common tooling restores or analyzes UPX-packed code. Use it for distribution size only, verify its license/exception for the release, and measure startup, code signing, updater delta size, platform policy, and AV/EDR reputation. Pack before signing.

[VMProtect](https://vmpsoft.com/) and [Oreans](https://www.oreans.com/) products such as Themida, WinLicense, and Code Virtualizer are established commercial Windows candidates. Their value comes from selected mutation, packing, control-flow transformation, and instruction virtualization, plus supported maps and automation. They are not a reason to virtualize the whole application. Start with one or two stable crown-jewel routines, exclude startup/hot loops/crash handlers/third-party code, and run the full release gate. Commercial protectors become privileged build dependencies: pin the installer/digest and policy, isolate their CI execution, inventory bundled runtimes/drivers, and keep signing keys outside them.

### Anti-debugging and anti-instrumentation

Local checks such as debugger APIs, timing, parent-process inspection, executable-page scans, breakpoint detection, `ptrace` state, root/jailbreak indicators, and hook detection are individually patchable. Use several low-cost signals only when they change a server-side risk decision or materially delay a selected patch path.

- Keep a support/debug channel for signed internal builds; do not ship a universal bypass token.
- Avoid kernel drivers and undocumented platform APIs unless the product requirement, signing/update lifecycle, and incident owner justify them.
- Avoid destructive or irreversible responses. Record bounded telemetry, re-challenge the session, reduce high-risk operations, or require fresh server authorization.
- Make telemetry privacy-bounded and rate-limited. An analyst can forge or suppress client telemetry.
- Test profilers, crash reporters, accessibility software, overlays, endpoint security, virtualization, compatibility layers, rooted/jailbroken devices, and clock/CPU variance.

### Integrity and tamper response

Prefer trust anchored outside the mutable payload:

1. OS/app-store signature and notarization for publisher identity and artifact integrity.
2. Signed update metadata binding product, platform, version, digest, size, expiry, and rollout channel.
3. Signed manifest for immutable resources and plugins, verified before load.
4. Server nonce/challenge bound to session, account, build, and expiry when runtime attestation is available.
5. In-process self-checks as redundant tripwires, never the sole enforcement point.

A self-hash routine and its expected digest reside in the same patchable process. An external launcher is also client-controlled unless anchored by enforced platform policy or a server challenge. Define behavior for signature expiry, offline use, partial update, clock rollback, corrupted resources, and recovery.

### Licensing

Use signed entitlements, not encrypted client booleans. A compact offline token can contain:

```json
{
  "schema": 1,
  "product": "PRODUCT",
  "license_id": "SERIAL",
  "subject": "ACCOUNT_OR_DEVICE",
  "features": ["FEATURE_A"],
  "not_before": "TIMESTAMP",
  "expires_at": "TIMESTAMP",
  "max_version": "VERSION",
  "nonce": "NONCE"
}
```

Canonicalize and sign these bytes with an established signature scheme and a private key held in an HSM/offline signing service. Ship only the public verification key. For online products, renew short-lived leases and enforce concurrency, revocation, refunds, and clock policy on the server. Device binding needs reset/privacy/support flows. Obfuscate the client verification path only as a delay layer; a patcher can replace a local `valid` branch.

## 9. Independent before/after verification

Never judge protection from its configuration file. Compare three artifacts where practical: debug/reference, normal release, and protected release. Give a blind analyst only the shipped artifact and public product behavior, not source, ground truth, mappings, seeds, or protector settings.

### Static evidence

Run the bundled evidence adapter into separate no-clobber receipts:

```text
python <skill-dir>/scripts/evidence_adapter.py binary \
  --target BASELINE_BINARY --tool strings --tool objdump \
  --include-string-values --include-previews \
  --output ARTIFACT_DIR/baseline-binary.json

python <skill-dir>/scripts/evidence_adapter.py binary \
  --target PROTECTED_BINARY --tool strings --tool objdump \
  --include-string-values --include-previews \
  --output ARTIFACT_DIR/protected-binary.json
```

Keep these opt-in leakage receipts private: they intentionally retain bounded redacted strings and analyzer previews. For ELF, prefer `readelf` plus `objdump`; for PE, use `dumpbin`, `objdump`, or `rabin2`; for Mach-O, use `otool`; use only installed profiles. The adapter always adds bounded built-in hashes/header/ASCII/UTF-16 evidence. A receipt proves what ran and what was observed, not that the binary is resistant.

Wrap a selected headless decompiler as a direct argv vector (`shell=False`):

```text
python <skill-dir>/scripts/evidence_adapter.py binary \
  --target TARGET --output ARTIFACT_DIR/decompiler.json -- \
  analyzeHeadless PROJECT_DIR PROJECT_NAME -import TARGET -analysisTimeoutPerFile TIMEOUT
```

For IDA, Ghidra, Binary Ninja, Rizin/radare2, JADX, ILSpy, dnSpy-style tooling, `javap`, Wasm decompilers, or engine-specific extractors, use the installed CLI or a bounded manual session and preserve its exact version, argv, project digest, logs, and report digest. Test at least:

- source/build paths, repository names, user names, debug sections, source maps, PDB/dSYM links, and compiler metadata
- secrets and secret-shaped values; API routes, feature flags, protocol messages, SQL, panic/assert/log text, license strings, and asset keys
- imports, exports, symbols, reflection/type metadata, Objective-C selectors, Go runtime names, .NET IL, JVM classes, Wasm exports, and engine metadata
- recognizable high-value functions, cross-references, constants, state machines, patch points, and the shortest path around the local decision
- signature, notarization, manifest, and update verification on the final bytes

Search for known canaries, not just random strings. A zero-hit `strings` result does not establish protection; decode routines and runtime plaintext may still expose every value.

### Dynamic and operational evidence

Use the same test corpus, machine class, network conditions, account state, and profiler for A and B. Measure:

| Gate | Minimum evidence |
| --- | --- |
| Functional equivalence | Unit/integration/e2e/update/offline tests; legitimate license and expiry paths; plugin/reflection/JNI/FFI behavior |
| Analyst cost | Blind time-to-locate target, reconstruct algorithm/protocol, extract selected asset, patch decision, and produce a working modified artifact |
| Leakage | Sensitive canary hits, exported names, type/method recovery, source paths, source maps, metadata, and runtime plaintext capture |
| Performance | Artifact/download size, build time, startup, steady memory, CPU, p50/p95/p99 hot-path latency or frame time, battery where relevant |
| Reliability | Crash/hang rate, exception/panic behavior, symbolicated crash proof, upgrade/downgrade/rollback, corrupted/partial update recovery |
| Reproducibility | Same inputs produce the required deterministic artifact, or documented seeded diversity with recoverable maps and provenance |
| Endpoint/store compatibility | Private enterprise AV/EDR staging, platform signing/notarization/store review, accessibility/profilers/overlays, clean VM/device install |
| Supply chain | Pinned protector/compiler digest, SBOM/license, isolated build receipt, final signature, update metadata, retained rollback artifact |

Do not upload unreleased proprietary binaries to public multi-scanner services without an explicit disclosure decision. Use private vendor portals, enterprise EDR staging, or isolated endpoints. Establish reputation before a wide rollout and keep a kill switch at the distribution/update layer for a bad protected release.

### A/B decision rule

Accept a protection layer only when all mandatory correctness/signing/update/crash gates pass and its measured analyst-delay value exceeds its operational cost. Record rejected variants too. Typical outcomes:

- **Ship baseline** when symbols/paths/maps were the main leak and stripping/minification removed them.
- **Add selective string hiding** when named non-secret literals materially accelerate discovery and runtime cost stays bounded.
- **Add selective virtualization** when a small stable algorithm or offline-license path has high value and blind analysis shows a material delay.
- **Move the decision server-side** when the asset is an entitlement, payment, signing secret, durable key, game state, or frequently changed rule.
- **Drop the protector** when it mainly increases AV flags, crash opacity, startup time, update size, or support load without delaying the selected recovery/patch task.

### Executable Protection Lab

Put target-specific acceptance criteria in a small JSON manifest and run the same manifest against normal and protected artifacts. Inputs may be one file, a directory, or a ZIP-like package; directory traversal never follows symlinks or Windows reparse points, and archives are inventoried without extraction.

```json
{
  "schema_version": 1,
  "name": "desktop-release",
  "canaries": ["LICENSE_DECISION_CANARY", "PRIVATE_ROUTE_CANARY"],
  "thresholds": {
    "max_size_growth_percent": 25,
    "max_protected_canary_hits": 0,
    "min_canary_reduction": 2,
    "max_source_maps_with_content": 0,
    "require_protected_digest_change": true
  },
  "gates": [
    {
      "id": "functional-smoke",
      "roles": ["baseline", "protected"],
      "argv": ["TEST_RUNNER", "--artifact", "{artifact}"],
      "mandatory": true,
      "expect_exit_codes": [0]
    },
    {
      "id": "signature-and-update",
      "roles": ["protected"],
      "argv": ["VERIFY_RELEASE", "{artifact}"],
      "mandatory": true,
      "expect_exit_codes": [0]
    }
  ]
}
```

```text
python <skill-dir>/scripts/protection_lab.py \
  --manifest GATES.json --baseline RELEASE --protected PROTECTED \
  --output protection-receipt.json
```

Gate argv is an explicit array executed with `shell=False`. Use `{artifact}`, `{artifact_dir}`, and `{role}` placeholders. Optional `cwd`, `max_duration_ms`, `require_equal_stdout`, and `require_equal_stderr` bind functional, performance, crash-symbol, signing, updater, rollback, decompiler, debugger, and AV/EDR checks without teaching the lab product-specific behavior. Environment override values are never recorded.

The receipt contains full artifact or bounded-inventory digests, separate inventory/content-scan truncation flags, size and file deltas, extension and source-map counts, full SHA-256 canary identities and hit locations, exact tool versions and redacted argv, bounded stream digests, unavailable coverage, every threshold, and the final `ship`, `reject`, or `deferred` decision. Canary thresholds require at least one canary. No-follow file handles plus fd-relative directory traversal where supported, with identity/reparse revalidation elsewhere, reject symlink/reparse swaps. Every artifact is inventoried again after gates; changed or unavailable final bytes reject the release and retain the post-gate digest/status. A bounded content scan defers only a selected canary/source-map threshold that depends on complete leakage coverage; bounded inventory still defers the artifact. Gate roles are unique and aggregate timeout/capture budgets bound the run matrix. `ship` means every selected mandatory gate passed; it is not a universal protection score. Increase bounds or add the missing real tool when a required surface is deferred.

## 10. Release checklist

- [ ] Named assets, adversary tier, useful protection lifetime, and cost ceilings are explicit.
- [ ] Long-lived secrets and authoritative decisions are absent from client artifacts.
- [ ] Stable release baseline passes before any obfuscator/protector is introduced.
- [ ] One exact pinned transformation stack is used; no redundant packer/obfuscator chain.
- [ ] Public exports/reflection/keep rules are minimized and externally tested.
- [ ] PDB/dSYM/debug files, source maps, deobfuscation maps, seeds, and build receipts are archived privately.
- [ ] The shipped binary/package contains no unintended source, maps, paths, test data, credentials, or signing material.
- [ ] Protection runs before final code signing; signatures/notarization and signed update metadata verify on final bytes.
- [ ] Functional, crash-symbolication, performance, update, rollback, offline, AV/EDR, and store/platform gates pass.
- [ ] Blind A/B evidence shows a material increase in time or effort for the selected analyst task.
- [ ] Monitoring and rollout can identify and stop a bad protected release without exposing signing roots.
- [ ] Residual recoverability under local administrator/root and dynamic instrumentation is stated plainly.

## Primary sources

- Rust: [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html), [rustc code-generation options](https://doc.rust-lang.org/rustc/codegen-options/index.html), [`obfstr`](https://github.com/CasualX/obfstr), [`obfustr`](https://github.com/de-vri-es/obfustr-rs), [`cryptify`](https://github.com/dronavallipranav/rust-obfuscator), and [`rust_code_obfuscator`](https://github.com/GianIac/rustfuscator).
- Go: [`go build`](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies) and [garble documentation](https://github.com/burrowers/garble).
- Native formats/toolchains: [GNU Binutils](https://sourceware.org/binutils/docs/), [MSVC compiler/linker options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-alphabetically), and [Apple code-signing workflow](https://developer.apple.com/documentation/security/updating-mac-software).
- .NET: [Native AOT deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/), [trimming](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/trim-self-contained), and [single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview).
- Android/JVM: [R8 code/resource shrinking](https://developer.android.com/build/shrink-code), [Android Keystore](https://developer.android.com/privacy-and-security/keystore), [Play Integrity](https://developer.android.com/google/play/integrity), [ProGuard](https://github.com/Guardsquare/proguard), and [yGuard](https://github.com/yWorks/yGuard).
- Electron/JavaScript: [Electron security](https://www.electronjs.org/docs/latest/tutorial/security), [ASAR archives](https://www.electronjs.org/docs/latest/tutorial/asar-archives), and [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses).
- Python: [Cython documentation](https://cython.readthedocs.io/en/latest/), [Nuitka user manual](https://nuitka.net/user-documentation/user-manual.html), and [PyInstaller operating model](https://pyinstaller.org/en/stable/operating-mode.html).
- Apple/mobile: [Apple Platform Security](https://support.apple.com/guide/security/welcome/web), [Xcode build settings](https://developer.apple.com/documentation/xcode/build-settings-reference), and [OWASP MASVS resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/).
- WebAssembly: [Binaryen](https://github.com/WebAssembly/binaryen), [WABT](https://github.com/WebAssembly/wabt), and [WebAssembly security model](https://webassembly.org/docs/security/).
- Games: [Unity managed code stripping](https://docs.unity3d.com/Manual/managed-code-stripping.html), [Unity IL2CPP](https://docs.unity3d.com/Manual/IL2CPP.html), and [Unreal Engine packaging](https://dev.epicgames.com/documentation/en-us/unreal-engine/packaging-your-project).
- Update/signing: [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) and [Microsoft Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode).

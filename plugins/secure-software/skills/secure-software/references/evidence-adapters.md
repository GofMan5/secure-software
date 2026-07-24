# Evidence adapters

Use the bundled adapter when reproducible tool or runtime receipts materially strengthen an attack path. Scanner output remains a candidate lead: it does not become a finding without source/control/sink reachability and counterevidence.

The adapter uses only the Python standard library and starts commands with `shell=False`. On Windows, the operating system may still route `.cmd` or `.bat` launchers through its command processor; prefer a real executable or an explicit interpreter argv when that distinction matters. Every receipt records the resolved executable, best-effort tool version, redacted argv, working directory, environment-variable names (never values), UTC timing, exit code, timeout, byte counts, truncation, SHA-256 digests, normalized observations, and collection errors. Output is an atomic no-clobber write; add `--force` to replace it.

## Scanner evidence

Run every matching installed project-native dependency scanner (`cargo-audit`, `npm audit`, `govulncheck`, or `pip-audit`):

```text
python <skill-dir>/scripts/evidence_adapter.py scan --scope TARGET --output scanner.json
```

Select one or more adapters explicitly:

```text
python <skill-dir>/scripts/evidence_adapter.py scan --scope TARGET --tool cargo-audit --tool npm-audit --output scanner.json
```

Supported profiles are `auto`, `cargo-audit`, `npm-audit`, `semgrep`, `bandit`, `pip-audit`, `trivy`, `osv-scanner`, `checkov`, `tfsec`, `gosec`, `govulncheck`, and `detect-secrets`. `auto` expands to every matching installed project-native dependency scanner and deduplicates explicit selections. Python discovery supports `requirements.txt`, `pyproject.toml`, and `pylock.toml`/`pylock.*.toml`; lock files use `pip-audit --locked`. Tools are used only when installed; the adapter does not install or download them. Some scanners may fetch their normal advisory or rules data.

Ingest one or more existing SARIF 2.1.0 artifacts without executing a scanner:

```text
python <skill-dir>/scripts/evidence_adapter.py scan --scope TARGET --sarif RESULT.sarif --output scanner.json
```

Wrap any already-installed scanner as an argv vector after `--`:

```text
python <skill-dir>/scripts/evidence_adapter.py scan --scope TARGET --output scanner.json -- TOOL ARG1 ARG2
```

JSON and SARIF output is normalized into bounded `candidate_lead` observations when recognized. The original stdout and stderr SHA-256 digests and exit status remain in `runs`; raw previews are omitted by default. Add `--include-previews` only when the local receipt needs bounded redacted output. A scanner's nonzero "findings present" exit is evidence, not automatically an adapter error.

## Binary and decompiler evidence

The binary mode always records file metadata and SHA-256, distinguishes PE, ELF, thin/fat Mach-O, and Java class headers, and extracts bounded ASCII and UTF-16LE strings. `auto` then selects the first installed native analyzer suitable for the format:

```text
python <skill-dir>/scripts/evidence_adapter.py binary --target TARGET --output binary.json
```

Run selected analyzers in addition to the built-in receipt:

```text
python <skill-dir>/scripts/evidence_adapter.py binary --target TARGET --tool readelf --tool strings --output binary.json
```

Supported profiles and their exact argv are:

| Profile | Argv |
| --- | --- |
| `objdump` | `objdump -x TARGET` |
| `readelf` | `readelf -a TARGET` |
| `strings` | `strings -a -n MIN TARGET` |
| `rabin2` | `rabin2 -Ij TARGET` |
| `dumpbin` | `dumpbin /headers /imports TARGET` |
| `otool` | `otool -hvL TARGET` |

Wrap a headless decompiler, disassembler, managed-code inspector, or protocol decoder directly:

```text
python <skill-dir>/scripts/evidence_adapter.py binary --target TARGET --output decompiler.json -- DECOMPILER ARG1 ARG2
```

Cross-platform preference order:

| Target | Preferred installed tool | Fallback |
| --- | --- | --- |
| PE on Windows | `dumpbin`, GNU/LLVM `objdump`, or `rabin2` | built-in header/hash/strings; run `Get-AuthenticodeSignature` through explicit `powershell` argv when signature evidence is needed |
| ELF on Linux/WSL | `readelf`, then `objdump` or `rabin2` | built-in header/hash/strings |
| Mach-O on macOS | `otool`, then `objdump` or `rabin2` | built-in header/hash/strings; use `codesign` as custom argv for signature evidence |
| .NET/JVM/Android | `ilspycmd`, `javap`, `jadx`, or `apktool` as custom argv | built-in artifact receipt plus the platform tool available in the session |
| Native decompilation | Ghidra headless, Rizin/radare2, Binary Ninja, or another installed CLI as custom argv | preserve the built-in receipt and mark unavailable decompiler coverage explicitly |

Tune bounded extraction with `--strings-bytes`, `--strings-min`, and `--strings-limit`. The defaults inspect at most 8 MiB for 200 strings of four or more printable characters; the full file is still streamed for SHA-256. String offsets, encodings, and lengths are recorded by default while values are omitted. Add `--include-string-values` for a private canary/leakage analysis.

## Runtime evidence

HTTP uses verified standard-library networking and defaults to `HEAD`. TLS uses the platform trust store, validates the hostname, and records the negotiated protocol/cipher plus a DER certificate digest:

```text
python <skill-dir>/scripts/evidence_adapter.py runtime --http https://HOST/health --tls HOST:443 --output runtime.json
```

Use `--http-method GET --http-body-bytes N` only when body evidence is needed. The digest is explicitly labeled `captured-prefix` when the configured body bound is reached.

Docker and Kubernetes probes are read-only and timeout-bounded:

```text
python <skill-dir>/scripts/evidence_adapter.py runtime --docker --kubectl --output runtime.json
```

They execute `docker version --format {{json .}}`, `kubectl version --output=json`, and `kubectl auth can-i --list --all-namespaces`. Docker Desktop supplies both CLIs on Windows; native Docker/Kubernetes CLIs are used on Linux and macOS. HTTP/TLS remain the dependency-free fallback when those CLIs or their runtime credentials are absent.

Wrap another runtime collector as a direct argv vector (`shell=False`):

```text
python <skill-dir>/scripts/evidence_adapter.py runtime --cwd TARGET --output runtime.json -- TOOL ARG1 ARG2
```

Pass a required process environment value with `--env NAME=VALUE`. Only `NAME` is stored; explicit values, credential-shaped tokens, sensitive argv values, URL credentials, and query values are removed from opt-in previews. Redaction cannot classify every target-defined secret, so keep receipts private and use scoped credentials. Prefer credential-provider or platform-native environment injection so secrets do not enter terminal history.

## Receipt contract

`schema_version: 1` has one stable top-level shape:

```json
{
  "schema_version": 1,
  "adapter": {"name": "secure-software-evidence", "version": "1.0"},
  "kind": "scanner | binary | runtime",
  "scope": "TARGET",
  "started_at": "UTC timestamp",
  "finished_at": "UTC timestamp",
  "duration_ms": 0,
  "host": {},
  "artifacts": [],
  "runs": [],
  "observations": [],
  "errors": []
}
```

Each subprocess stream is consumed continuously: all bytes contribute to its raw SHA-256 and byte count while only `--max-output-bytes` are retained. A truncated or redaction-expanded preview is omitted, keeping secret prefixes at the capture boundary out of the receipt. On Windows the process starts suspended, enters a kill-on-close Job Object, then resumes; if containment cannot be established, execution stops. POSIX commands run in a fresh process group that is terminated at completion or timeout; use an external container/VM boundary for tools that deliberately detach into a new session. HTTP redirects, body reads, TCP connect, and TLS handshake share a monotonic deadline. A receipt with `errors` is still written and the adapter exits nonzero, so missing tools and partial runtime coverage remain machine-visible.

Run the offline regression check after packaging or editing:

```text
python <skill-dir>/scripts/evidence_adapter.py --self-test
```

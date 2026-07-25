#!/usr/bin/env python3
"""Run and score a blind, paired Secure Software A/B benchmark."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import random
import re
import signal
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = ROOT / "benchmark" / "chainbench-12.json"
VARIANTS = ("baseline", "treatment")
DISPOSITIONS = {"reportable", "suppressed", "not_applicable", "deferred"}
SEVERITIES = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
EDGE_KINDS = ("entry", "source", "control", "bypass", "sink", "impact")
CHAINBENCH_FAMILIES = {
    "tenant-authorization",
    "desktop-ipc-updater",
    "cicd-provenance",
    "cloud-iam",
    "rag-mcp",
    "game-reward-replay",
}
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 4096
MAX_WORKSPACE_FILE_BYTES = 16 * 1024 * 1024
MAX_WORKSPACE_TOTAL_BYTES = 64 * 1024 * 1024
BLIND_ID = re.compile(r"r-[0-9a-f]{16}")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
BASE_ENV_KEYS = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "LANG", "LC_ALL"}
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in "123456789¹²³"),
    *(f"LPT{i}" for i in "123456789¹²³"),
}
MAX_LOCAL_PYTHON_FILES = 256
MAX_LOCAL_PYTHON_BYTES = 16 * 1024 * 1024
CONTEXT_TEXT_FIELDS = ("client", "model", "reasoning", "executor", "network")
CONTEXT_DIGEST_FIELDS = ("profile_sha256", "skill_sha256", "tools_sha256")

RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ChainBench result",
    "type": "object",
    "required": ["schema_version", "candidates"],
    "properties": {
        "schema_version": {"const": 1},
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "disposition", "severity", "confidence", "root_cause", "chain"],
                "properties": {
                    "title": {"type": "string"},
                    "disposition": {"enum": sorted(DISPOSITIONS)},
                    "severity": {"enum": list(SEVERITIES)},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "root_cause": {
                        "type": "object",
                        "required": ["summary", "citations"],
                        "properties": {
                            "summary": {"type": "string"},
                            "citations": {"$ref": "#/$defs/citations"},
                        },
                    },
                    "chain": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["kind", "citations"],
                            "properties": {
                                "kind": {"enum": list(EDGE_KINDS)},
                                "citations": {"$ref": "#/$defs/citations"},
                            },
                        },
                    },
                    "siblings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["citations"],
                            "properties": {"citations": {"$ref": "#/$defs/citations"}},
                        },
                    },
                },
            },
        },
        "usage": {
            "type": "object",
            "properties": {
                "input_tokens": {"type": "integer", "minimum": 0},
                "output_tokens": {"type": "integer", "minimum": 0},
                "total_tokens": {"type": "integer", "minimum": 0},
            },
        },
    },
    "$defs": {
        "citations": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "required": ["path", "line", "quote"],
                "properties": {
                    "path": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                    "quote": {"type": "string"},
                },
            },
        }
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def byte_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    require(os.path.lexists(path), f"{label} file is missing")
    require(not path.is_symlink(), f"{label} must be a regular file, not a symlink")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode), f"{label} must be a regular file")
        require(info.st_size <= limit, f"{label} exceeds {limit} bytes")
        raw = handle.read(limit + 1)
    require(len(raw) <= limit, f"{label} exceeds {limit} bytes")
    return raw


class StreamDigest:
    def __init__(self) -> None:
        self.bytes = 0
        self.digest = hashlib.sha256()

    def read(self, stream: Any) -> None:
        try:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                self.bytes += len(chunk)
                self.digest.update(chunk)
        except (OSError, ValueError):
            pass
        finally:
            stream.close()


def stop_process(proc: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt" and shutil.which("taskkill"):
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        elif os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        if proc.poll() is None:
            proc.kill()


def create_kill_job(proc: subprocess.Popen[bytes]) -> Any:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        configured = kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
        assigned = configured and kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(proc._handle))
        if not assigned:
            kernel32.CloseHandle(job)
            return None
        return job
    except (AttributeError, OSError):
        return None


def resume_suspended_process(proc: subprocess.Popen[bytes]) -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class ThreadEntry(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG), ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            return False
        try:
            entry = ThreadEntry(dwSize=ctypes.sizeof(ThreadEntry))
            found = kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.th32OwnerProcessID == proc.pid:
                    thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                    if not thread:
                        return False
                    try:
                        return kernel32.ResumeThread(thread) != 0xFFFFFFFF
                    finally:
                        kernel32.CloseHandle(thread)
                found = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
            return False
        finally:
            kernel32.CloseHandle(snapshot)
    except (AttributeError, OSError):
        return False


def close_process_group(proc: subprocess.Popen[bytes], job: Any) -> None:
    if os.name == "nt":
        if job:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle(job)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def safe_relative_path(raw: str) -> PurePosixPath:
    require(isinstance(raw, str) and raw, "fixture path must be a non-empty string")
    path = PurePosixPath(raw)
    require(not path.is_absolute() and ".." not in path.parts and "." not in path.parts, f"unsafe fixture path: {raw}")
    require(path.as_posix() == raw, f"fixture path must be canonical: {raw}")
    require("\\" not in raw, f"fixture path must use '/': {raw}")
    require(re.match(r"^[A-Za-z]:", raw) is None and all(":" not in part for part in path.parts), f"drive-like fixture path: {raw}")
    for part in path.parts:
        require(len(part.encode("utf-8")) <= 255, f"fixture path component exceeds 255 UTF-8 bytes: {raw}")
        require(part == part.rstrip(" ."), f"fixture path has a trailing dot or space: {raw}")
        require(not any(ord(char) < 32 or char in '<>"|?*' for char in part), f"fixture path is not portable: {raw}")
        require(part.split(".", 1)[0].upper() not in WINDOWS_RESERVED, f"fixture path uses a Windows device name: {raw}")
    return path


def portable_path_key(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(part.casefold() for part in path.parts)


def fixture_digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        raw = files[name].encode("utf-8")
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def snapshot_tree(root: Path) -> tuple[str, dict[str, dict[str, Any]], bool]:
    entries: dict[str, dict[str, Any]] = {}
    truncated = False
    total_bytes = 0
    if root.exists():
        for index, path in enumerate(root.rglob("*"), 1):
            if index > MAX_WORKSPACE_ENTRIES:
                truncated = True
                break
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entries[relative] = {"type": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                size = path.stat().st_size
                total_bytes += size
                bounded = size > MAX_WORKSPACE_FILE_BYTES or total_bytes > MAX_WORKSPACE_TOTAL_BYTES
                entries[relative] = {
                    "type": "file",
                    "size": size,
                    "sha256": None if bounded else file_digest(path),
                }
                truncated = truncated or bounded
            elif path.is_dir():
                entries[relative] = {"type": "directory"}
            else:
                entries[relative] = {"type": "other"}
    return canonical_digest({"entries": entries, "truncated": truncated}), entries, truncated


def changed_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return [name for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]


def validate_anchor(anchor: Any, files: dict[str, str], label: str) -> None:
    require(isinstance(anchor, dict), f"{label} anchor must be an object")
    path = anchor.get("path")
    start = anchor.get("start")
    end = anchor.get("end")
    require(path in files, f"{label} anchor path is missing: {path}")
    lines = files[path].splitlines()
    require(isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= len(lines), f"{label} anchor range is invalid: {anchor}")


def validate_chain_truth(truth: Any, files: dict[str, str], label: str) -> None:
    require(isinstance(truth, dict), f"{label} truth must be an object")
    required_edges = truth.get("required_edges")
    match_edges = truth.get("match_edges")
    root_cause = truth.get("root_cause")
    require(isinstance(required_edges, dict) and set(required_edges) == set(EDGE_KINDS), f"all chain edges are required: {label}")
    require(isinstance(match_edges, list) and len(match_edges) >= 2 and set(match_edges) <= set(EDGE_KINDS), f"invalid match edges: {label}")
    require(isinstance(root_cause, list) and root_cause, f"root_cause is required: {label}")
    for edge, anchors in required_edges.items():
        require(isinstance(anchors, list) and anchors, f"missing {edge} anchors: {label}")
        for anchor in anchors:
            validate_anchor(anchor, files, f"{label}/{edge}")
    for anchor in root_cause:
        validate_anchor(anchor, files, f"{label}/root_cause")


def validate_suite(suite: Any) -> dict[str, Any]:
    require(isinstance(suite, dict) and suite.get("schema_version") == 1, "suite schema_version must be 1")
    suite_id = suite.get("suite_id")
    cases = suite.get("cases")
    require(isinstance(suite_id, str) and suite_id, "suite_id is required")
    require(isinstance(cases, list) and cases, "suite cases must be a non-empty list")
    ids: set[str] = set()
    pairs: dict[str, list[dict[str, Any]]] = {}
    case_digests: dict[str, str] = {}

    for case in cases:
        require(isinstance(case, dict), "each case must be an object")
        case_id = case.get("id")
        pair_id = case.get("pair_id")
        family = case.get("family")
        kind = case.get("kind")
        prompt = case.get("prompt")
        files = case.get("files")
        truth = case.get("truth")
        require(isinstance(case_id, str) and case_id and case_id not in ids, f"invalid or duplicate case id: {case_id}")
        require(isinstance(pair_id, str) and pair_id, f"pair_id is required for {case_id}")
        require(isinstance(family, str) and family, f"family is required for {case_id}")
        require(kind in {"vulnerable", "near_miss"}, f"invalid kind for {case_id}")
        require(isinstance(prompt, str) and prompt.strip(), f"prompt is required for {case_id}")
        require(isinstance(files, dict) and files, f"virtual files are required for {case_id}")
        require(isinstance(truth, dict), f"truth is required for {case_id}")
        ids.add(case_id)
        pairs.setdefault(pair_id, []).append(case)

        paths: list[tuple[str, ...]] = []
        fixture_entries: set[tuple[str, ...]] = set()
        fixture_bytes = 0
        for name, content in files.items():
            key = portable_path_key(safe_relative_path(name))
            require(key not in paths, f"case-insensitive fixture path collision: {case_id}/{name}")
            require(not any(key[:len(other)] == other or other[:len(key)] == key for other in paths),
                    f"fixture file/directory prefix collision: {case_id}/{name}")
            paths.append(key)
            require(isinstance(content, str), f"fixture file must be text: {case_id}/{name}")
            raw_content = content.encode("utf-8")
            require(len(raw_content) <= MAX_WORKSPACE_FILE_BYTES, f"fixture file exceeds {MAX_WORKSPACE_FILE_BYTES} bytes: {case_id}/{name}")
            fixture_bytes += len(raw_content)
            require(fixture_bytes <= MAX_WORKSPACE_TOTAL_BYTES, f"fixture exceeds {MAX_WORKSPACE_TOTAL_BYTES} bytes: {case_id}")
            fixture_entries.update(key[:index] for index in range(1, len(key) + 1))
            require(len(fixture_entries) <= MAX_WORKSPACE_ENTRIES, f"fixture exceeds {MAX_WORKSPACE_ENTRIES} entries: {case_id}")
        case_digests[case_id] = fixture_digest(files)

        expected = truth.get("expected_disposition")
        require(expected in DISPOSITIONS, f"invalid expected disposition for {case_id}")
        if kind == "vulnerable":
            require(expected == "reportable", f"vulnerable case must be reportable: {case_id}")
            severity = truth.get("severity")
            require(severity in SEVERITIES and severity != "none", f"invalid vulnerable severity: {case_id}")
            validate_chain_truth(truth, files, case_id)
            siblings = truth.get("siblings")
            require(isinstance(siblings, list), f"siblings must be an array: {case_id}")
            for index, sibling in enumerate(siblings):
                validate_chain_truth(sibling, files, f"{case_id}/siblings/{index}")
        else:
            require(expected == "suppressed", f"near-miss case must be suppressed: {case_id}")
            closure = truth.get("closure")
            require(isinstance(closure, list) and closure, f"near-miss closure is required: {case_id}")
            for anchor in closure:
                validate_anchor(anchor, files, f"{case_id}/closure")

    for pair_id, pair_cases in pairs.items():
        require(len(pair_cases) == 2, f"pair must contain exactly two cases: {pair_id}")
        require({case["kind"] for case in pair_cases} == {"vulnerable", "near_miss"}, f"pair must contain vulnerable and near-miss: {pair_id}")
        require(len({case["family"] for case in pair_cases}) == 1, f"pair family mismatch: {pair_id}")
        require(len({case["prompt"] for case in pair_cases}) == 1, f"paired prompts must be identical: {pair_id}")
        require(len({tuple(sorted(case["files"])) for case in pair_cases}) == 1, f"paired file layouts must match: {pair_id}")

    if suite_id.startswith("chainbench-12"):
        require(len(cases) == 12 and len(pairs) == 6, "ChainBench-12 requires six vulnerable/near-miss pairs")
        require({case["family"] for case in cases} == CHAINBENCH_FAMILIES, "ChainBench-12 family coverage mismatch")

    return {
        "schema_version": 1,
        "suite_id": suite_id,
        "suite_sha256": canonical_digest(suite),
        "cases": len(cases),
        "pairs": len(pairs),
        "fixture_sha256": case_digests,
    }


def load_suite(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    suite = read_json(path)
    report = validate_suite(suite)
    return suite, report


def build_plan(suite: dict[str, Any], repeats: int, seed: int) -> dict[str, Any]:
    require(isinstance(repeats, int) and repeats > 0, "repeats must be positive")
    report = validate_suite(suite)
    rng = random.Random(f"{seed}:{report['suite_sha256']}")
    entries: list[dict[str, Any]] = []
    for repeat in range(1, repeats + 1):
        for case in suite["cases"]:
            pair = [
                {"case_id": case["id"], "repeat": repeat, "variant": variant,
                 "fixture_sha256": report["fixture_sha256"][case["id"]]}
                for variant in VARIANTS
            ]
            rng.shuffle(pair)
            entries.extend(pair)
    rng.shuffle(entries)
    seen: set[str] = set()
    for entry in entries:
        while True:
            blind_id = f"r-{rng.getrandbits(64):016x}"
            if blind_id not in seen:
                seen.add(blind_id)
                break
        entry["blind_id"] = blind_id
    return {
        "schema_version": 1,
        "suite_id": suite["suite_id"],
        "suite_sha256": report["suite_sha256"],
        "repeats": repeats,
        "seed": seed,
        "runs": entries,
    }


def validate_plan(plan: Any, suite: dict[str, Any]) -> None:
    report = validate_suite(suite)
    require(isinstance(plan, dict) and plan.get("schema_version") == 1, "plan schema_version must be 1")
    require(plan.get("suite_id") == suite["suite_id"], "plan suite id mismatch")
    require(plan.get("suite_sha256") == report["suite_sha256"], "plan suite digest mismatch")
    repeats = plan.get("repeats")
    runs = plan.get("runs")
    require(isinstance(repeats, int) and repeats > 0 and isinstance(runs, list), "invalid plan")
    expected_cases = {case["id"] for case in suite["cases"]}
    require(len(runs) == len(expected_cases) * repeats * 2, "plan run count mismatch")
    blind_ids: set[str] = set()
    triples: set[tuple[str, int, str]] = set()
    observed: dict[tuple[str, int], set[str]] = {}
    for run in runs:
        require(isinstance(run, dict), "plan run must be an object")
        blind_id = run.get("blind_id")
        case_id = run.get("case_id")
        repeat = run.get("repeat")
        variant = run.get("variant")
        fixture_sha256 = run.get("fixture_sha256")
        require(isinstance(blind_id, str) and BLIND_ID.fullmatch(blind_id) and blind_id not in blind_ids, "duplicate or invalid blind id")
        require(case_id in expected_cases and isinstance(repeat, int) and 1 <= repeat <= repeats, "invalid case/repeat in plan")
        require(variant in VARIANTS, "invalid variant in plan")
        expected_fixture = fixture_digest(next(case["files"] for case in suite["cases"] if case["id"] == case_id))
        require(fixture_sha256 == expected_fixture, "plan fixture digest mismatch")
        triple = (case_id, repeat, variant)
        require(triple not in triples, "duplicate case/repeat/variant in plan")
        blind_ids.add(blind_id)
        triples.add(triple)
        observed.setdefault((case_id, repeat), set()).add(variant)
    require(len(observed) == len(expected_cases) * repeats, "plan is missing a case/repeat pair")
    require(all(variants == set(VARIANTS) for variants in observed.values()), "every case/repeat must have both variants")


def parse_command(raw: str) -> list[str]:
    try:
        command = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"command must be a JSON argv array: {error}") from error
    require(isinstance(command, list) and command and all(isinstance(item, str) and item for item in command), "command must be a non-empty JSON string array")
    return command


def expand_command(template: list[str], values: dict[str, str]) -> list[str]:
    command: list[str] = []
    for item in template:
        expanded = item
        for name, value in values.items():
            expanded = expanded.replace("{" + name + "}", value)
        command.append(expanded)
    return command


def runner_environment(pass_env: list[str]) -> dict[str, str]:
    names = set(BASE_ENV_KEYS)
    for name in pass_env:
        require(ENV_NAME.fullmatch(name) is not None, f"invalid --pass-env name: {name}")
        require(name in os.environ, f"--pass-env is not set: {name}")
        names.add(name)
    return {**{name: os.environ[name] for name in names if name in os.environ}, "PYTHONDONTWRITEBYTECODE": "1"}


def validate_run_context(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} context must be a JSON object")
    expected = {*CONTEXT_TEXT_FIELDS, *CONTEXT_DIGEST_FIELDS, "token_budget"}
    require(set(value) == expected, f"{label} context fields must be exactly: {', '.join(sorted(expected))}")
    for field in CONTEXT_TEXT_FIELDS:
        require(isinstance(value.get(field), str) and value[field].strip(), f"{label} context.{field} is required")
    for field in CONTEXT_DIGEST_FIELDS:
        digest = value.get(field)
        require(digest == "absent" or isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
                f"{label} context.{field} must be SHA-256 or absent")
    require(isinstance(value.get("token_budget"), int) and not isinstance(value["token_budget"], bool) and value["token_budget"] > 0,
            f"{label} context.token_budget must be positive")
    return value


def validate_context_pair(contexts: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    baseline = validate_run_context(contexts.get("baseline"), "baseline")
    treatment = validate_run_context(contexts.get("treatment"), "treatment")
    for field in (*CONTEXT_TEXT_FIELDS, "token_budget", "tools_sha256"):
        require(baseline[field] == treatment[field], f"A/B context mismatch: {field}")
    require(baseline["profile_sha256"] not in {"absent", treatment["profile_sha256"]}
            and treatment["profile_sha256"] != "absent", "A/B profiles must be present and distinct")
    require(baseline["skill_sha256"] == "absent" and treatment["skill_sha256"] != "absent",
            "baseline skill must be absent and treatment skill must be frozen")
    return baseline, treatment


def local_python_dependencies(entry: Path) -> dict[str, str]:
    root = entry.parent
    while (root / "__init__.py").is_file():
        root = root.parent
    pending = [entry]
    files: dict[str, str] = {}
    total_bytes = 0
    # ponytail: bounded static imports; dynamic imports belong in the explicit tools_sha256 manifest.
    while pending:
        path = pending.pop().resolve()
        key = str(path)
        if key in files:
            continue
        require(len(files) < MAX_LOCAL_PYTHON_FILES, "local Python dependency graph exceeds 256 files")
        raw = path.read_bytes()
        total_bytes += len(raw)
        require(total_bytes <= MAX_LOCAL_PYTHON_BYTES, "local Python dependency graph exceeds 16 MiB")
        files[key] = byte_digest(raw)
        try:
            tree = compile(raw, key, "exec", ast.PyCF_ONLY_AST)
        except (SyntaxError, ValueError) as error:
            raise ValueError(f"cannot inspect local Python imports in {path}: {error}") from error

        relative = path.relative_to(root)
        module_parts = relative.with_suffix("").parts
        package_parts = relative.parent.parts if path.name == "__init__.py" else module_parts[:-1]
        imports: list[tuple[int, tuple[str, ...]]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend((0, tuple(alias.name.split("."))) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = tuple(node.module.split(".")) if node.module else ()
                if node.level:
                    keep = len(package_parts) - node.level + 1
                    if keep < 0:
                        continue
                    base = package_parts[:keep] + base
                imports.append((0, base))
                imports.extend((0, base + tuple(alias.name.split("."))) for alias in node.names if alias.name != "*")

        for _, parts in imports:
            if not parts:
                continue
            for index in range(1, len(parts) + 1):
                package = root.joinpath(*parts[:index], "__init__.py")
                if package.is_file():
                    pending.append(package)
            module = root.joinpath(*parts).with_suffix(".py")
            package = root.joinpath(*parts, "__init__.py")
            if module.is_file():
                pending.append(module)
            elif package.is_file():
                pending.append(package)
    return files


def run_context_digest(command: list[str], environment: dict[str, str], timeout: float,
                       isolation: str, context: dict[str, Any]) -> str:
    files: dict[str, str] = {}
    executable = shutil.which(command[0], path=environment.get("PATH"))
    for raw in ([executable] if executable else []) + command:
        if not raw or "{" in raw or "}" in raw:
            continue
        path = Path(raw).expanduser()
        if path.is_file():
            resolved = path.resolve()
            files[str(resolved)] = file_digest(resolved)
            if resolved.suffix.casefold() == ".py":
                files.update(local_python_dependencies(resolved))
    return canonical_digest({
        "context": context,
        "command_template": command,
        "command_files": files,
        "environment": environment,
        "timeout_seconds": timeout,
        "isolation": isolation,
    })


def materialize_fixture(workspace: Path, files: dict[str, str]) -> None:
    expected: set[str] = set()
    for raw_name, content in files.items():
        relative = safe_relative_path(raw_name)
        expected.add(relative.as_posix())
        destination = workspace.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    actual = {path.relative_to(workspace).as_posix() for path in workspace.rglob("*") if path.is_file()}
    require(actual == expected, "materialized fixture manifest mismatch")


def citation_errors(citations: Any, label: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(citations, list) or len(citations) > 3:
        return [f"{label} citations must be an array with at most three items"]
    for index, citation in enumerate(citations):
        if not isinstance(citation, dict):
            errors.append(f"{label} citation {index} must be an object")
            continue
        if not isinstance(citation.get("path"), str) or not citation["path"]:
            errors.append(f"{label} citation {index} path is invalid")
        if not isinstance(citation.get("line"), int) or citation["line"] < 1:
            errors.append(f"{label} citation {index} line is invalid")
        if not isinstance(citation.get("quote"), str):
            errors.append(f"{label} citation {index} quote is invalid")
    return errors


def validate_result(result: Any) -> list[str]:
    if not isinstance(result, dict) or result.get("schema_version") != 1:
        return ["result schema_version must be 1"]
    candidates = result.get("candidates")
    if not isinstance(candidates, list):
        return ["result candidates must be an array"]
    errors: list[str] = []
    for index, candidate in enumerate(candidates):
        label = f"candidate {index}"
        if not isinstance(candidate, dict):
            errors.append(f"{label} must be an object")
            continue
        if not isinstance(candidate.get("title"), str) or not candidate["title"].strip():
            errors.append(f"{label} title is invalid")
        disposition = candidate.get("disposition")
        severity = candidate.get("severity")
        if disposition not in DISPOSITIONS:
            errors.append(f"{label} disposition is invalid")
        if severity not in SEVERITIES:
            errors.append(f"{label} severity is invalid")
        elif disposition == "reportable" and severity == "none":
            errors.append(f"{label} reportable severity must not be none")
        confidence = candidate.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            errors.append(f"{label} confidence is invalid")
        root_cause = candidate.get("root_cause")
        if not isinstance(root_cause, dict) or not isinstance(root_cause.get("summary"), str):
            errors.append(f"{label} root_cause is invalid")
        else:
            errors.extend(citation_errors(root_cause.get("citations"), f"{label} root_cause"))
        chain = candidate.get("chain")
        if not isinstance(chain, list):
            errors.append(f"{label} chain must be an array")
        else:
            for edge_index, edge in enumerate(chain):
                if not isinstance(edge, dict) or edge.get("kind") not in EDGE_KINDS:
                    errors.append(f"{label} chain edge {edge_index} is invalid")
                    continue
                errors.extend(citation_errors(edge.get("citations"), f"{label} chain edge {edge_index}"))
        siblings = candidate.get("siblings", [])
        if not isinstance(siblings, list):
            errors.append(f"{label} siblings must be an array")
        else:
            for sibling_index, sibling in enumerate(siblings):
                if not isinstance(sibling, dict):
                    errors.append(f"{label} sibling {sibling_index} must be an object")
                    continue
                errors.extend(citation_errors(sibling.get("citations"), f"{label} sibling {sibling_index}"))
    usage = result.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            errors.append("usage must be an object")
        else:
            for field in ("input_tokens", "output_tokens", "total_tokens"):
                value = usage.get(field)
                if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                    errors.append(f"usage.{field} is invalid")
    return errors


def normalized_tokens(result: Any) -> dict[str, int] | None:
    if not isinstance(result, dict) or not isinstance(result.get("usage"), dict):
        return None
    usage = result["usage"]
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    total_tokens = usage.get("total_tokens")
    if isinstance(total_tokens, int) and not isinstance(total_tokens, bool) and total_tokens >= 0:
        return {
            "input": input_tokens if isinstance(input_tokens, int) and input_tokens >= 0 else 0,
            "output": output_tokens if isinstance(output_tokens, int) and output_tokens >= 0 else 0,
            "total": total_tokens,
        }
    if all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (input_tokens, output_tokens)):
        return {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens}
    return None


def run_one(
    run: dict[str, Any],
    case: dict[str, Any],
    command_template: list[str],
    results_root: Path,
    timeout: float,
    environment: dict[str, str],
    isolation: str,
    suite_sha256: str,
    run_context: dict[str, Any],
    run_context_sha256: str,
) -> None:
    blind_id = run["blind_id"]
    destination = results_root / blind_id
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chainbench-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        control = root / "control"
        output = control / "result.json"
        prompt = control / "prompt.txt"
        schema = control / "result-schema.json"
        workspace.mkdir()
        control.mkdir()
        materialize_fixture(workspace, case["files"])
        prompt.write_text(
            case["prompt"].rstrip()
            + "\n\nTreat the supplied workspace as read-only. Write exactly one JSON object matching the supplied schema to the output path.",
            encoding="utf-8",
        )
        write_json(schema, RESULT_SCHEMA)
        before_digest, before_entries, before_truncated = snapshot_tree(workspace)
        require(not before_truncated, "materialized fixture exceeds workspace snapshot limits")
        values = {
            "workspace": str(workspace.resolve()),
            "prompt": str(prompt.resolve()),
            "output": str(output.resolve()),
            "schema": str(schema.resolve()),
            "blind_id": blind_id,
        }
        command = expand_command(command_template, values)
        started = time.perf_counter()
        stdout = StreamDigest()
        stderr = StreamDigest()
        exit_code: int | None = None
        timed_out = False
        execution_error: str | None = None
        proc: subprocess.Popen[bytes] | None = None
        job: Any = None
        group_closed = False
        try:
            flags = (subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004) if os.name == "nt" else 0
            proc = subprocess.Popen(
                command,
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=flags,
                start_new_session=os.name != "nt",
            )
            job = create_kill_job(proc)
            assert proc.stdout is not None and proc.stderr is not None
            if os.name == "nt" and (not job or not resume_suspended_process(proc)):
                close_process_group(proc, job)
                group_closed = True
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
                proc.stdout.close()
                proc.stderr.close()
                raise OSError("unable to establish Windows process-tree containment")
            readers = [
                threading.Thread(target=stdout.read, args=(proc.stdout,), daemon=True),
                threading.Thread(target=stderr.read, args=(proc.stderr,), daemon=True),
            ]
            for reader in readers:
                reader.start()
            try:
                remaining = timeout - (time.perf_counter() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                exit_code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                close_process_group(proc, job)
                group_closed = True
            if proc.poll() is None:
                try:
                    exit_code = proc.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    stop_process(proc)
                    exit_code = proc.wait(timeout=1)
            for reader in readers:
                reader.join(timeout=max(0.0, timeout - (time.perf_counter() - started)))
            if any(reader.is_alive() for reader in readers):
                timed_out = True
                proc.stdout.close()
                proc.stderr.close()
                for reader in readers:
                    reader.join(timeout=0.25)
                if any(reader.is_alive() for reader in readers):
                    raise OSError("subprocess capture threads did not stop")
        except (OSError, subprocess.SubprocessError) as error:
            execution_error = f"{type(error).__name__}: {error}"
        finally:
            if proc is not None and not group_closed:
                close_process_group(proc, job)
        after_digest, after_entries, after_truncated = snapshot_tree(workspace)
        changes = changed_paths(before_entries, after_entries)

        result_value: Any = None
        result_errors = ["result file is missing"]
        output_sha256: str | None = None
        if os.path.lexists(output):
            try:
                raw = read_bounded_regular(output, MAX_RESULT_BYTES, "result")
            except (OSError, ValueError) as error:
                result_errors = [str(error)]
            else:
                output_sha256 = byte_digest(raw)
                (destination / "result.json").write_bytes(raw)
                try:
                    result_value = json.loads(raw, object_pairs_hook=unique_object)
                    result_errors = validate_result(result_value)
                except (UnicodeDecodeError, ValueError) as error:
                    result_errors = [f"invalid result JSON: {error}"]
        duration = round(time.perf_counter() - started, 6)

        receipt = {
            "schema_version": 1,
            "blind_id": blind_id,
            "suite_sha256": suite_sha256,
            "fixture_sha256": fixture_digest(case["files"]),
            "command_template_sha256": canonical_digest(command_template),
            "command_sha256": canonical_digest(command),
            "run_context": run_context,
            "run_context_sha256": run_context_sha256,
            "environment_keys": sorted(environment),
            "isolation": isolation,
            "timeout_seconds": timeout,
            "mutation_scope": "workspace",
            "exit_code": exit_code,
            "timed_out": timed_out,
            "execution_error": execution_error,
            "duration_seconds": duration,
            "before_sha256": before_digest,
            "after_sha256": after_digest,
            "unsafe_mutation": before_digest != after_digest,
            "snapshot_truncated": after_truncated,
            "changed_paths": changes,
            "stdout_bytes": stdout.bytes,
            "stdout_sha256": stdout.digest.hexdigest(),
            "stderr_bytes": stderr.bytes,
            "stderr_sha256": stderr.digest.hexdigest(),
            "output_sha256": output_sha256,
            "output_valid": not result_errors and exit_code == 0 and not timed_out and execution_error is None,
            "output_errors": result_errors,
            "tokens": normalized_tokens(result_value),
        }
        write_json(destination / "receipt.json", receipt)


def run_plan(
    suite: dict[str, Any],
    plan: dict[str, Any],
    results_root: Path,
    baseline: list[str],
    treatment: list[str],
    timeout: float,
    overwrite: bool,
    pass_env: list[str],
    isolation: str,
    contexts: dict[str, dict[str, Any]],
) -> None:
    validate_plan(plan, suite)
    require(timeout > 0, "timeout must be positive")
    cases = {case["id"]: case for case in suite["cases"]}
    environment = runner_environment(pass_env)
    baseline_context, treatment_context = validate_context_pair(contexts)
    context_digests = {
        "baseline": run_context_digest(baseline, environment, timeout, isolation, baseline_context),
        "treatment": run_context_digest(treatment, environment, timeout, isolation, treatment_context),
    }
    results_root.mkdir(parents=True, exist_ok=True)
    for index, run in enumerate(plan["runs"], start=1):
        destination = results_root / run["blind_id"]
        template = baseline if run["variant"] == "baseline" else treatment
        if not overwrite and (destination / "receipt.json").is_file():
            _, receipt, valid = load_artifact(results_root, run["blind_id"])
            current = (
                valid and receipt is not None
                and receipt.get("suite_sha256") == plan["suite_sha256"]
                and receipt.get("fixture_sha256") == run["fixture_sha256"]
                and receipt.get("command_template_sha256") == canonical_digest(template)
                and receipt.get("run_context_sha256") == context_digests[run["variant"]]
                and receipt.get("isolation") == isolation
                and receipt.get("timeout_seconds") == timeout
                and receipt.get("environment_keys") == sorted(environment)
            )
            require(current, f"stale or incomplete result for {run['blind_id']}; pass --overwrite")
            print(f"[{index}/{len(plan['runs'])}] {run['blind_id']}: exists")
            continue
        if overwrite and destination.exists():
            shutil.rmtree(destination)
        print(f"[{index}/{len(plan['runs'])}] {run['blind_id']}: running")
        run_one(run, cases[run["case_id"]], template, results_root, timeout, environment, isolation,
                plan["suite_sha256"], baseline_context if run["variant"] == "baseline" else treatment_context,
                context_digests[run["variant"]])


def record_result(plan: dict[str, Any], results_root: Path, blind_id: str, output_path: Path, receipt_path: Path) -> None:
    runs = {run["blind_id"]: run for run in plan.get("runs", []) if isinstance(run, dict) and isinstance(run.get("blind_id"), str)}
    require(BLIND_ID.fullmatch(blind_id) is not None and blind_id in runs, f"blind id is not in the plan: {blind_id}")
    require(receipt_path.is_file(), "output and receipt files are required")
    raw = read_bounded_regular(output_path, MAX_RESULT_BYTES, "result")
    try:
        result = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"invalid result JSON: {error}") from error
    errors = validate_result(result)
    receipt = read_json(receipt_path)
    require(isinstance(receipt, dict), "receipt must be an object")
    validate_run_context(receipt.get("run_context"), "receipt")
    require(isinstance(receipt.get("duration_seconds"), (int, float)) and receipt["duration_seconds"] >= 0, "receipt duration is required")
    require(all(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", receipt[key]) for key in
                ("before_sha256", "after_sha256", "command_sha256", "command_template_sha256", "run_context_sha256")),
            "receipt digests are required")
    require(receipt.get("suite_sha256") == plan.get("suite_sha256"), "receipt suite digest mismatch")
    require(receipt.get("fixture_sha256") == runs[blind_id].get("fixture_sha256"), "receipt fixture digest mismatch")
    require(receipt.get("exit_code") == 0 and receipt.get("timed_out") is False, "receipt execution did not complete cleanly")
    require(receipt.get("isolation") in {"workspace-only", "external-sandbox"}, "receipt isolation is required")
    require(isinstance(receipt.get("timeout_seconds"), (int, float)) and not isinstance(receipt["timeout_seconds"], bool)
            and receipt["timeout_seconds"] > 0, "receipt timeout is required")
    require(receipt.get("mutation_scope") == "workspace", "receipt mutation scope must be workspace")
    for key in ("variant", "case_id", "pair_id", "kind", "truth"):
        receipt.pop(key, None)
    receipt.update(
        {
            "schema_version": 1,
            "blind_id": blind_id,
            "unsafe_mutation": receipt["before_sha256"] != receipt["after_sha256"],
            "output_sha256": byte_digest(raw),
            "output_valid": not errors and receipt.get("exit_code", 0) == 0 and not receipt.get("timed_out", False)
                            and receipt.get("execution_error") is None,
            "output_errors": errors,
            "tokens": normalized_tokens(result) or receipt.get("tokens"),
        }
    )
    destination = results_root / blind_id
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "result.json").write_bytes(raw)
    write_json(destination / "receipt.json", receipt)


def source_line(case: dict[str, Any], path: str, line: int) -> str | None:
    content = case["files"].get(path)
    if content is None:
        return None
    lines = content.splitlines()
    if line < 1 or line > len(lines):
        return None
    return lines[line - 1]


def citation_is_exact(case: dict[str, Any], citation: dict[str, Any]) -> bool:
    line = source_line(case, citation.get("path"), citation.get("line"))
    return line is not None and citation.get("quote") == line


def citation_matches_anchor(citation: dict[str, Any], anchor: dict[str, Any], case: dict[str, Any]) -> bool:
    return (
        citation_is_exact(case, citation)
        and citation.get("path") == anchor["path"]
        and anchor["start"] <= citation.get("line", 0) <= anchor["end"]
    )


def candidate_citations(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    citations: list[dict[str, Any]] = []
    root = candidate.get("root_cause")
    if isinstance(root, dict) and isinstance(root.get("citations"), list):
        citations.extend(item for item in root["citations"] if isinstance(item, dict))
    for edge in candidate.get("chain", []):
        if isinstance(edge, dict) and isinstance(edge.get("citations"), list):
            citations.extend(item for item in edge["citations"] if isinstance(item, dict))
    for sibling in candidate.get("siblings", []):
        if isinstance(sibling, dict) and isinstance(sibling.get("citations"), list):
            citations.extend(item for item in sibling["citations"] if isinstance(item, dict))
    return citations


def candidate_edge_matches(candidate: dict[str, Any], case: dict[str, Any], truth: dict[str, Any] | None = None) -> dict[str, bool]:
    required = (truth or case["truth"])["required_edges"]
    found: dict[str, bool] = {kind: False for kind in EDGE_KINDS}
    for edge in candidate.get("chain", []):
        if not isinstance(edge, dict) or edge.get("kind") not in required:
            continue
        kind = edge["kind"]
        for citation in edge.get("citations", []):
            if isinstance(citation, dict) and any(citation_matches_anchor(citation, anchor, case) for anchor in required[kind]):
                found[kind] = True
                break
    return found


def citations_match_anchors(citations: Any, anchors: list[dict[str, Any]], case: dict[str, Any]) -> bool:
    return isinstance(citations, list) and any(
        isinstance(citation, dict) and citation_matches_anchor(citation, anchor, case)
        for citation in citations
        for anchor in anchors
    )


def candidate_root_matches(candidate: dict[str, Any], case: dict[str, Any], truth: dict[str, Any] | None = None) -> bool:
    root = candidate.get("root_cause")
    return isinstance(root, dict) and citations_match_anchors(root.get("citations"), (truth or case["truth"])["root_cause"], case)


def candidate_matches_truth(candidate: dict[str, Any], case: dict[str, Any], truth: dict[str, Any]) -> bool:
    edges = candidate_edge_matches(candidate, case, truth)
    return all(edges[kind] for kind in truth["match_edges"]) and candidate_root_matches(candidate, case, truth)


def near_miss_is_explicit(candidates: list[dict[str, Any]], case: dict[str, Any]) -> bool:
    citations = [
        citation
        for candidate in candidates
        if candidate.get("disposition") == "suppressed" and candidate.get("severity") == "none"
        for citation in candidate_citations(candidate)
    ]
    return all(any(citation_matches_anchor(citation, anchor, case) for citation in citations) for anchor in case["truth"]["closure"])


def load_artifact(results_root: Path, blind_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool]:
    directory = results_root / blind_id
    result_path = directory / "result.json"
    receipt_path = directory / "receipt.json"
    if not os.path.lexists(result_path) or not receipt_path.is_file():
        return None, None, False
    try:
        raw = read_bounded_regular(result_path, MAX_RESULT_BYTES, "result")
        result = json.loads(raw, object_pairs_hook=unique_object)
        receipt = read_json(receipt_path)
        validate_run_context(receipt.get("run_context") if isinstance(receipt, dict) else None, "receipt")
    except (OSError, UnicodeDecodeError, ValueError):
        return None, None, False
    valid = (
        isinstance(receipt, dict)
        and receipt.get("blind_id") == blind_id
        and receipt.get("output_sha256") == byte_digest(raw)
        and receipt.get("output_valid") is True
        and receipt.get("exit_code") == 0
        and receipt.get("timed_out") is False
        and receipt.get("execution_error") is None
        and isinstance(receipt.get("before_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", receipt["before_sha256"])
        and isinstance(receipt.get("after_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", receipt["after_sha256"])
        and all(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", receipt[key]) for key in
                ("suite_sha256", "fixture_sha256", "command_sha256", "command_template_sha256", "run_context_sha256"))
        and receipt.get("isolation") in {"workspace-only", "external-sandbox"}
        and isinstance(receipt.get("timeout_seconds"), (int, float)) and not isinstance(receipt["timeout_seconds"], bool)
        and receipt["timeout_seconds"] > 0
        and receipt.get("mutation_scope") == "workspace"
        and isinstance(receipt.get("environment_keys"), list)
        and receipt.get("unsafe_mutation") is (receipt["before_sha256"] != receipt["after_sha256"])
        and not validate_result(result)
    )
    return result, receipt, valid


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def score_variant(entries: list[dict[str, Any]], cases: dict[str, dict[str, Any]], results_root: Path,
                  suite_sha256: str) -> dict[str, Any]:
    counters = {
        "runs": len(entries),
        "valid_outputs": 0,
        "vulnerable_runs": 0,
        "near_miss_runs": 0,
        "detected": 0,
        "complete": 0,
        "near_miss_rejected": 0,
        "external_isolation_runs": 0,
        "reportable_claims": 0,
        "true_positive_claims": 0,
        "false_positive_claims": 0,
        "false_high_critical": 0,
        "duplicates": 0,
        "root_cause_matches": 0,
        "sibling_anchors": 0,
        "sibling_matches": 0,
        "citations": 0,
        "exact_citations": 0,
        "unsafe_mutations": 0,
    }
    severity_errors: list[int] = []
    confidence_errors: list[float] = []
    durations: list[float] = []
    tokens: list[int] = []
    run_contexts: set[str] = set()
    context_manifests: dict[str, dict[str, Any]] = {}
    full_by_repeat: dict[int, int] = {}

    for run in entries:
        case = cases[run["case_id"]]
        result, receipt, valid = load_artifact(results_root, run["blind_id"])
        valid = bool(
            valid and receipt is not None
            and receipt.get("suite_sha256") == suite_sha256
            and receipt.get("fixture_sha256") == run["fixture_sha256"]
        )
        if valid and receipt:
            run_contexts.add(receipt["run_context_sha256"])
            context_manifests[canonical_digest(receipt["run_context"])] = receipt["run_context"]
            if valid and receipt.get("isolation") == "external-sandbox":
                counters["external_isolation_runs"] += 1
            if receipt.get("unsafe_mutation") is True:
                counters["unsafe_mutations"] += 1
            duration = receipt.get("duration_seconds")
            if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0:
                durations.append(float(duration))
            token_receipt = receipt.get("tokens")
            if isinstance(token_receipt, dict) and isinstance(token_receipt.get("total"), int) and token_receipt["total"] >= 0:
                tokens.append(token_receipt["total"])
        if valid:
            counters["valid_outputs"] += 1
        candidates = result["candidates"] if valid and result else []
        reportable = [candidate for candidate in candidates if candidate.get("disposition") == "reportable"]
        counters["reportable_claims"] += len(reportable)
        for candidate in candidates:
            for citation in candidate_citations(candidate):
                counters["citations"] += 1
                if citation_is_exact(case, citation):
                    counters["exact_citations"] += 1

        if case["kind"] == "near_miss":
            counters["near_miss_runs"] += 1
            counters["false_positive_claims"] += len(reportable)
            counters["false_high_critical"] += sum(candidate.get("severity") in {"high", "critical"} for candidate in reportable)
            confidence_errors.extend(float(candidate["confidence"]) ** 2 for candidate in reportable)
            explicit = valid and not reportable and near_miss_is_explicit(candidates, case)
            if explicit:
                counters["near_miss_rejected"] += 1
            suppression_confidence = max(
                (float(candidate["confidence"]) for candidate in candidates
                 if candidate.get("disposition") == "suppressed" and candidate.get("severity") == "none"),
                default=0.0,
            ) if explicit else 0.0
            confidence_errors.append((suppression_confidence - 1.0) ** 2)
            continue

        counters["vulnerable_runs"] += 1
        counters["sibling_anchors"] += len(case["truth"]["siblings"])
        scored: list[tuple[int, bool, bool, dict[str, Any]]] = []
        match_edges = case["truth"]["match_edges"]
        for index, candidate in enumerate(reportable):
            edges = candidate_edge_matches(candidate, case)
            matched = all(edges[edge] for edge in match_edges) and candidate_root_matches(candidate, case)
            complete = all(edges.values())
            scored.append((index, matched, complete, candidate))
        matches = [item for item in scored if item[1]]
        sibling_sets = {
            item[0]: {
                sibling_index
                for sibling_index, sibling in enumerate(case["truth"]["siblings"])
                if candidate_matches_truth(item[3], case, sibling)
            }
            for item in scored
        }
        true_items = [item for item in scored if item[1] or sibling_sets[item[0]]]
        unmatched = [item for item in scored if not item[1] and not sibling_sets[item[0]]]
        sibling_truth = set().union(*(sibling_sets[item[0]] for item in true_items)) if true_items else set()
        unique_truth = (1 if matches else 0) + len(sibling_truth)
        counters["true_positive_claims"] += min(len(true_items), unique_truth)
        counters["duplicates"] += max(0, len(true_items) - unique_truth)
        counters["sibling_matches"] += len(sibling_truth)
        confidence_errors.append((max((float(item[3]["confidence"]) for item in matches), default=0.0) - 1.0) ** 2)
        for sibling_index in range(len(case["truth"]["siblings"])):
            confidence_errors.append((max(
                (float(item[3]["confidence"]) for item in scored if sibling_index in sibling_sets[item[0]]),
                default=0.0,
            ) - 1.0) ** 2)
        confidence_errors.extend(float(item[3]["confidence"]) ** 2 for item in unmatched)
        counters["false_positive_claims"] += len(unmatched)
        counters["false_high_critical"] += sum(item[3].get("severity") in {"high", "critical"} for item in unmatched)
        if matches:
            counters["detected"] += 1
            best = max(
                matches,
                key=lambda item: (
                    item[2],
                    sum(candidate_edge_matches(item[3], case).values()),
                    -item[0],
                ),
            )
            predicted = SEVERITIES[best[3]["severity"]]
            expected = SEVERITIES[case["truth"]["severity"]]
            severity_errors.append(abs(predicted - expected))
            if candidate_root_matches(best[3], case):
                counters["root_cause_matches"] += 1
            if any(item[2] for item in matches):
                counters["complete"] += 1
                full_by_repeat[run["repeat"]] = full_by_repeat.get(run["repeat"], 0) + 1

    severity_mae = round(sum(severity_errors) / len(severity_errors), 6) if severity_errors else None
    confidence_brier = round(sum(confidence_errors) / len(confidence_errors), 6) if confidence_errors else None
    duration_median = round(statistics.median(durations), 6) if durations else None
    token_median = round(statistics.median(tokens), 6) if tokens else None
    return {
        **counters,
        "valid_output_rate": ratio(counters["valid_outputs"], counters["runs"]),
        "recall": ratio(counters["detected"], counters["vulnerable_runs"]),
        "precision": ratio(counters["true_positive_claims"], counters["reportable_claims"]),
        "complete_chain_rate": ratio(counters["complete"], counters["vulnerable_runs"]),
        "duplicate_rate": ratio(counters["duplicates"], counters["reportable_claims"]),
        "root_cause_recall": ratio(counters["root_cause_matches"], counters["vulnerable_runs"]),
        "sibling_recall": ratio(counters["sibling_matches"], counters["sibling_anchors"]),
        "severity_mae": severity_mae,
        "confidence_brier": confidence_brier,
        "citation_accuracy": ratio(counters["exact_citations"], counters["citations"]),
        "near_miss_rejection": ratio(counters["near_miss_rejected"], counters["near_miss_runs"]),
        "unsafe_mutation_rate": ratio(counters["unsafe_mutations"], counters["runs"]),
        "external_isolation_coverage": ratio(counters["external_isolation_runs"], counters["runs"]),
        "duration_seconds": {
            "count": len(durations),
            "median": duration_median,
            "total": round(sum(durations), 6),
        },
        "tokens": {
            "count": len(tokens),
            "coverage": ratio(len(tokens), counters["runs"]),
            "median": token_median,
            "total": sum(tokens),
        },
        "run_context_sha256": sorted(run_contexts),
        "run_contexts": [context_manifests[key] for key in sorted(context_manifests)],
        "complete_by_repeat": {str(key): full_by_repeat.get(key, 0) for key in sorted({run["repeat"] for run in entries})},
    }


def build_score(suite: dict[str, Any], plan: dict[str, Any], results_root: Path) -> dict[str, Any]:
    validate_plan(plan, suite)
    cases = {case["id"]: case for case in suite["cases"]}
    by_variant = {
        variant: score_variant([run for run in plan["runs"] if run["variant"] == variant], cases, results_root,
                               plan["suite_sha256"])
        for variant in VARIANTS
    }
    delta_fields = (
        "recall",
        "precision",
        "complete_chain_rate",
        "duplicate_rate",
        "root_cause_recall",
        "sibling_recall",
        "citation_accuracy",
        "near_miss_rejection",
        "unsafe_mutation_rate",
        "severity_mae",
        "confidence_brier",
    )
    delta: dict[str, float | None] = {}
    for field in delta_fields:
        baseline_value = by_variant["baseline"][field]
        treatment_value = by_variant["treatment"][field]
        delta[field] = round(treatment_value - baseline_value, 6) if baseline_value is not None and treatment_value is not None else None

    baseline = by_variant["baseline"]
    treatment = by_variant["treatment"]
    comparable_contexts = False
    if len(baseline["run_contexts"]) == len(treatment["run_contexts"]) == 1:
        try:
            validate_context_pair({"baseline": baseline["run_contexts"][0], "treatment": treatment["run_contexts"][0]})
            comparable_contexts = True
        except ValueError:
            pass
    repeat_passes = sum(value >= 5 for value in treatment["complete_by_repeat"].values())
    gate_checks = {
        "at_least_three_repeats": plan["repeats"] >= 3,
        "all_outputs_valid": all(result["valid_outputs"] == result["runs"] for result in by_variant.values()),
        "one_frozen_context_per_variant": all(len(result["run_context_sha256"]) == 1 for result in by_variant.values()),
        "variant_contexts_are_distinct": baseline["run_context_sha256"] != treatment["run_context_sha256"],
        "contexts_preserve_ab_contract": comparable_contexts,
        "five_of_six_in_two_repeats": repeat_passes >= 2,
        "no_false_high_critical": treatment["false_high_critical"] == 0,
        "at_most_one_false_positive": treatment["false_positive_claims"] <= 1,
        "all_near_misses_explicitly_rejected": treatment["near_miss_rejection"] == 1.0,
        "complete_chain_rate_delta_at_least_0_20": delta["complete_chain_rate"] is not None and delta["complete_chain_rate"] >= 0.2,
        "root_cause_recall_at_least_0_833333": treatment["root_cause_recall"] >= 0.833333,
        "severity_mae_at_most_0_5": treatment["severity_mae"] is not None and treatment["severity_mae"] <= 0.5,
        "exact_citation_rate": treatment["citation_accuracy"] == 1.0,
        "token_usage_recorded": all(result["tokens"]["coverage"] == 1.0 for result in by_variant.values()),
        "no_unsafe_mutation": all(result["unsafe_mutations"] == 0 for result in by_variant.values()),
        "external_isolation_verified": baseline["external_isolation_coverage"] == 1.0 and treatment["external_isolation_coverage"] == 1.0,
    }
    return {
        "schema_version": 1,
        "suite_id": suite["suite_id"],
        "suite_sha256": canonical_digest(suite),
        "repeats": plan["repeats"],
        "variants": by_variant,
        "treatment_minus_baseline": delta,
        "release_gate": {"passed": all(gate_checks.values()), "checks": gate_checks},
    }


def self_test() -> None:
    default_suite, default_report = load_suite(DEFAULT_SUITE)
    require(default_report["cases"] == 12 and default_report["pairs"] == 6, "default ChainBench-12 is incomplete")
    mini_suite = {
        "schema_version": 1,
        "suite_id": "self-test",
        "cases": [
            {
                "id": "case-a",
                "pair_id": "pair-a",
                "family": "self-test",
                "kind": "vulnerable",
                "prompt": "Audit the supplied fixture.",
                "files": {"app.txt": "request = attacker_input\nresource = lookup_without_owner(request)\nauthorize = skipped\nreturn privileged_data(resource)\nimpact = cross_boundary_read\nsibling_request = attacker_input\nsibling_resource = lookup_without_owner(sibling_request)\nsibling_authorize = skipped\nsibling_return = privileged_data(sibling_resource)\nsibling_impact = cross_boundary_read\n"},
                "truth": {
                    "expected_disposition": "reportable",
                    "severity": "high",
                    "match_edges": ["control", "sink"],
                    "required_edges": {
                        "entry": [{"path": "app.txt", "start": 1, "end": 1}],
                        "source": [{"path": "app.txt", "start": 1, "end": 1}],
                        "control": [{"path": "app.txt", "start": 2, "end": 2}],
                        "bypass": [{"path": "app.txt", "start": 3, "end": 3}],
                        "sink": [{"path": "app.txt", "start": 4, "end": 4}],
                        "impact": [{"path": "app.txt", "start": 5, "end": 5}],
                    },
                    "root_cause": [{"path": "app.txt", "start": 2, "end": 3}],
                    "siblings": [{
                        "match_edges": ["control", "sink"],
                        "required_edges": {
                            "entry": [{"path": "app.txt", "start": 6, "end": 6}],
                            "source": [{"path": "app.txt", "start": 6, "end": 6}],
                            "control": [{"path": "app.txt", "start": 7, "end": 7}],
                            "bypass": [{"path": "app.txt", "start": 8, "end": 8}],
                            "sink": [{"path": "app.txt", "start": 9, "end": 9}],
                            "impact": [{"path": "app.txt", "start": 10, "end": 10}],
                        },
                        "root_cause": [{"path": "app.txt", "start": 7, "end": 8}],
                    }],
                },
            },
            {
                "id": "case-b",
                "pair_id": "pair-a",
                "family": "self-test",
                "kind": "near_miss",
                "prompt": "Audit the supplied fixture.",
                "files": {"app.txt": "request = attacker_input\nresource = lookup_with_owner(request)\nauthorize = enforced\nreturn privileged_data(resource)\nimpact = same_owner_read\nsibling_request = attacker_input\nsibling_resource = lookup_with_owner(sibling_request)\nsibling_authorize = enforced\nsibling_return = privileged_data(sibling_resource)\nsibling_impact = same_owner_read\n"},
                "truth": {
                    "expected_disposition": "suppressed",
                    "closure": [{"path": "app.txt", "start": 2, "end": 3}, {"path": "app.txt", "start": 7, "end": 8}],
                },
            },
        ],
    }
    validate_suite(mini_suite)
    plan = build_plan(mini_suite, repeats=1, seed=7)
    require(plan == build_plan(mini_suite, repeats=1, seed=7), "plan is not deterministic")
    require(all("baseline" not in run["blind_id"] and "treatment" not in run["blind_id"] for run in plan["runs"]), "blind ids leak variants")
    changed_suite = json.loads(json.dumps(mini_suite))
    changed_suite["cases"][0]["files"]["app.txt"] += "revision = changed\n"
    changed_plan = build_plan(changed_suite, repeats=1, seed=7)
    require([run["blind_id"] for run in changed_plan["runs"]] != [run["blind_id"] for run in plan["runs"]],
            "blind ids are not bound to the suite digest")
    require(not near_miss_is_explicit([], mini_suite["cases"][1]),
            "empty output received near-miss closure credit")
    weak_sibling = {
        "root_cause": {"citations": [{"path": "app.txt", "line": 6, "quote": source_line(mini_suite["cases"][0], "app.txt", 6)}]},
        "chain": [{"kind": "impact", "citations": [{"path": "app.txt", "line": 6,
                                                       "quote": source_line(mini_suite["cases"][0], "app.txt", 6)}]}],
    }
    require(not candidate_matches_truth(weak_sibling, mini_suite["cases"][0], mini_suite["cases"][0]["truth"]["siblings"][0]),
            "single sibling citation received true-positive credit")
    bad_result = {"schema_version": 1, "candidates": [{
        "title": "invalid", "disposition": "reportable", "severity": "none", "confidence": 0.5,
        "root_cause": {"summary": "invalid", "citations": []}, "chain": [],
    }]}
    require(any("must not be none" in error for error in validate_result(bad_result)),
            "reportable finding with severity none was accepted")
    try:
        json.loads('{"duplicate": 1, "duplicate": 2}', object_pairs_hook=unique_object)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON key was accepted")
    for names, expected_error in (({"A.txt": "x", "a.txt": "y"}, "case-insensitive"),
                                  ({"dir": "x", "dir/file.txt": "y"}, "prefix")):
        invalid_paths = json.loads(json.dumps(mini_suite))
        invalid_paths["cases"][0]["files"] = names
        try:
            validate_suite(invalid_paths)
        except ValueError as error:
            require(expected_error in str(error), f"unexpected path-collision error: {error}")
        else:
            raise AssertionError("fixture path collision was accepted")
    for unsafe_path, expected_error in (("a" * 256, "255 UTF-8 bytes"),
                                        ("COM\u00b9.txt", "device name"),
                                        ("LPT\u00b2.log", "device name")):
        try:
            safe_relative_path(unsafe_path)
        except ValueError as error:
            require(expected_error in str(error), f"unexpected portable-path error: {error}")
        else:
            raise AssertionError(f"non-portable fixture path was accepted: {unsafe_path}")

    fake_runner_source = r'''import argparse, json
import fake_helper
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--mode", required=True)
p.add_argument("--workspace", required=True)
p.add_argument("--prompt", required=True)
p.add_argument("--output", required=True)
p.add_argument("--schema", required=True)
p.add_argument("--blind-id", required=True)
a = p.parse_args()
workspace = Path(a.workspace)
lines = (workspace / "app.txt").read_text(encoding="utf-8").splitlines()
vulnerable = "without_owner" in lines[1]

def cite(kind, line):
    return {"kind": kind, "citations": [{"path": "app.txt", "line": line, "quote": lines[line - 1]}]}

def candidate(disposition, severity, chain, root_line=2):
    return {
        "title": "fixture candidate",
        "disposition": disposition,
        "severity": severity,
        "confidence": 0.9,
        "root_cause": {"summary": "fixture root", "citations": [{"path": "app.txt", "line": root_line, "quote": lines[root_line - 1]}]},
        "chain": chain,
        "siblings": [],
    }

if a.mode == "treatment":
    if vulnerable:
        chain = [cite("entry", 1), cite("source", 1), cite("control", 2), cite("bypass", 3), cite("sink", 4), cite("impact", 5)]
        sibling = [cite("entry", 6), cite("source", 6), cite("control", 7), cite("bypass", 8), cite("sink", 9), cite("impact", 10)]
        candidates = [candidate("reportable", "high", chain), candidate("reportable", "high", sibling, 7)]
    else:
        candidates = [candidate("suppressed", "none", [cite("control", 2), cite("control", 7)])]
    usage = {"input_tokens": 20, "output_tokens": 10, "total_tokens": 30}
else:
    if vulnerable:
        partial = [cite("control", 2), cite("sink", 4)]
        candidates = [candidate("reportable", "critical", partial), candidate("reportable", "critical", partial)]
    else:
        candidates = [candidate("reportable", "high", [cite("control", 2)])]
        (workspace / "app.txt").write_text("\n".join(lines) + "\nchanged\n", encoding="utf-8")
    usage = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}

Path(a.output).write_text(json.dumps({"schema_version": 1, "candidates": candidates, "usage": usage}), encoding="utf-8")
'''
    with tempfile.TemporaryDirectory(prefix="chainbench-self-test-") as temporary:
        root = Path(temporary)
        bounded_file = root / "bounded.json"
        bounded_file.write_bytes(b"{}")
        require(read_bounded_regular(bounded_file, 2, "result") == b"{}", "bounded regular-file read failed")
        symlink_file = root / "bounded-link.json"
        try:
            symlink_file.symlink_to(bounded_file)
        except OSError:
            pass
        else:
            try:
                read_bounded_regular(symlink_file, 2, "result")
            except ValueError as error:
                require("not a symlink" in str(error), f"unexpected symlink error: {error}")
            else:
                raise AssertionError("symlinked result was accepted")
        snapshot_root = root / "snapshot-limit"
        snapshot_root.mkdir()
        with (snapshot_root / "oversized.bin").open("wb") as handle:
            handle.truncate(MAX_WORKSPACE_FILE_BYTES + 1)
        _, snapshot_entries, snapshot_truncated = snapshot_tree(snapshot_root)
        require(snapshot_truncated and snapshot_entries["oversized.bin"]["sha256"] is None,
                "oversized workspace file was fully hashed")
        fake_runner = root / "fake_runner.py"
        fake_helper = root / "fake_helper.py"
        fake_helper.write_text("VALUE = 1\n", encoding="utf-8")
        fake_runner.write_text(fake_runner_source, encoding="utf-8")
        results = root / "results"
        common = [
            sys.executable,
            str(fake_runner),
            "--mode",
            "MODE",
            "--workspace",
            "{workspace}",
            "--prompt",
            "{prompt}",
            "--output",
            "{output}",
            "--schema",
            "{schema}",
            "--blind-id",
            "{blind_id}",
        ]
        baseline = ["baseline" if item == "MODE" else item for item in common]
        treatment = ["treatment" if item == "MODE" else item for item in common]
        contexts = {
            "baseline": {
                "client": "self-test@1", "model": "fixture-snapshot", "reasoning": "fixed",
                "executor": "fake-runner@1", "network": "none", "token_budget": 100,
                "profile_sha256": byte_digest(b"baseline-profile"), "skill_sha256": "absent",
                "tools_sha256": byte_digest(b"fixture-tools"),
            },
            "treatment": {
                "client": "self-test@1", "model": "fixture-snapshot", "reasoning": "fixed",
                "executor": "fake-runner@1", "network": "none", "token_budget": 100,
                "profile_sha256": byte_digest(b"treatment-profile"), "skill_sha256": byte_digest(b"secure-software"),
                "tools_sha256": byte_digest(b"fixture-tools"),
            },
        }
        context_env = "CHAINBENCH_SELF_TEST_CONTEXT"
        previous_context_env = os.environ.get(context_env)
        os.environ[context_env] = "A"
        run_plan(mini_suite, plan, results, baseline, treatment, timeout=10, overwrite=False,
                 pass_env=[context_env], isolation="external-sandbox", contexts=contexts)
        summary = build_score(mini_suite, plan, results)
        require(summary == build_score(mini_suite, plan, results), "scoring is not deterministic")
        require(not summary["release_gate"]["passed"] and not summary["release_gate"]["checks"]["at_least_three_repeats"],
                "release gate accepted fewer than three repeats")
        require("complete_chain_rate_delta_at_least_0_20" in summary["release_gate"]["checks"]
                and "recall_delta_at_least_0_20" not in summary["release_gate"]["checks"],
                "release gate does not report the metric it checks")
        require(summary["release_gate"]["checks"]["all_outputs_valid"], "complete self-test outputs were rejected")
        baseline_score = summary["variants"]["baseline"]
        treatment_score = summary["variants"]["treatment"]
        require(baseline_score["recall"] == 1.0 and baseline_score["precision"] == 0.333333, "baseline recall/precision regression")
        require(baseline_score["complete_chain_rate"] == 0.0 and baseline_score["duplicates"] == 1, "baseline chain/duplicate regression")
        require(baseline_score["severity_mae"] == 1.0 and baseline_score["near_miss_rejection"] == 0.0, "baseline severity/control regression")
        require(baseline_score["root_cause_recall"] == 1.0 and baseline_score["confidence_brier"] == 0.705, "baseline root/confidence regression")
        require(baseline_score["unsafe_mutations"] == 1 and baseline_score["citation_accuracy"] == 1.0, "baseline mutation/citation regression")
        require(treatment_score["recall"] == 1.0 and treatment_score["precision"] == 1.0, "treatment recall/precision regression")
        require(treatment_score["true_positive_claims"] == 2 and treatment_score["sibling_recall"] == 1.0,
                "standalone sibling finding did not receive credit")
        require(treatment_score["complete_chain_rate"] == 1.0 and treatment_score["near_miss_rejection"] == 1.0, "treatment chain/control regression")
        require(treatment_score["severity_mae"] == 0.0 and treatment_score["unsafe_mutations"] == 0, "treatment severity/mutation regression")
        require(treatment_score["root_cause_recall"] == 1.0 and treatment_score["confidence_brier"] == 0.01, "treatment root/confidence regression")
        require(treatment_score["tokens"]["total"] == 60 and baseline_score["tokens"]["total"] == 30, "token aggregation regression")
        for run in plan["runs"]:
            receipt = read_json(results / run["blind_id"] / "receipt.json")
            require(not ({"variant", "case_id", "kind", "truth"} & set(receipt)), "receipt leaks benchmark truth")

        def expect_stale(label: str, candidate_timeout: float = 10) -> None:
            try:
                run_plan(mini_suite, plan, results, baseline, treatment, timeout=candidate_timeout, overwrite=False,
                         pass_env=[context_env], isolation="external-sandbox", contexts=contexts)
            except ValueError as error:
                require("stale or incomplete" in str(error), f"unexpected {label} error: {error}")
            else:
                raise AssertionError(f"stale cache accepted changed {label}")

        expect_stale("timeout", candidate_timeout=11)
        os.environ[context_env] = "B"
        expect_stale("environment")
        os.environ[context_env] = "A"
        fake_runner.write_text(fake_runner_source + "\n", encoding="utf-8")
        expect_stale("runner")
        fake_runner.write_text(fake_runner_source, encoding="utf-8")
        fake_helper.write_text("VALUE = 2\n", encoding="utf-8")
        expect_stale("runner helper")
        fake_helper.write_text("VALUE = 1\n", encoding="utf-8")
        mismatched_contexts = json.loads(json.dumps(contexts))
        mismatched_contexts["treatment"]["model"] = "different-model"
        try:
            run_plan(mini_suite, plan, results, baseline, treatment, timeout=10, overwrite=False,
                     pass_env=[context_env], isolation="external-sandbox", contexts=mismatched_contexts)
        except ValueError as error:
            require("A/B context mismatch" in str(error), f"unexpected context mismatch error: {error}")
        else:
            raise AssertionError("mismatched A/B context was accepted")

        child_runner = root / "child_runner.py"
        child_runner.write_text(r'''import argparse, json, subprocess, sys
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--output", required=True)
a = p.parse_args()
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
Path(a.output).write_text(json.dumps({"schema_version": 1, "candidates": []}), encoding="utf-8")
''', encoding="utf-8")
        child_template = [sys.executable, str(child_runner), "--output", "{output}"]
        child_environment = runner_environment([])
        child_results = root / "child-results"
        child_run = plan["runs"][0]
        run_one(child_run, {case["id"]: case for case in mini_suite["cases"]}[child_run["case_id"]], child_template,
                child_results, 0.5, child_environment, "external-sandbox", plan["suite_sha256"],
                contexts["baseline"],
                run_context_digest(child_template, child_environment, 0.5, "external-sandbox", contexts["baseline"]))
        child_receipt = read_json(child_results / child_run["blind_id"] / "receipt.json")
        require(child_receipt["duration_seconds"] < 1.0 and child_receipt["output_valid"] is True,
                "descendant process escaped the wall-clock deadline")

        limit_runner = root / "limit_runner.py"
        limit_runner.write_text(r'''import argparse, json, time
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--output", required=True)
p.add_argument("--size", type=int, default=0)
p.add_argument("--sleep", type=float, default=0)
a = p.parse_args()
time.sleep(a.sleep)
if a.size:
    Path(a.output).write_bytes(b"x" * a.size)
else:
    Path(a.output).write_text(json.dumps({"schema_version": 1, "candidates": []}), encoding="utf-8")
''', encoding="utf-8")
        limit_case = {case["id"]: case for case in mini_suite["cases"]}[child_run["case_id"]]
        oversize_template = [sys.executable, str(limit_runner), "--output", "{output}",
                             "--size", str(MAX_RESULT_BYTES + 1)]
        oversize_results = root / "oversize-results"
        run_one(child_run, limit_case, oversize_template, oversize_results, 10, child_environment,
                "external-sandbox", plan["suite_sha256"], contexts["baseline"],
                run_context_digest(oversize_template, child_environment, 10, "external-sandbox", contexts["baseline"]))
        oversize_receipt = read_json(oversize_results / child_run["blind_id"] / "receipt.json")
        require(oversize_receipt["output_sha256"] is None
                and oversize_receipt["output_errors"] == [f"result exceeds {MAX_RESULT_BYTES} bytes"],
                "oversized result was read or hashed before rejection")

        timeout_template = [sys.executable, str(limit_runner), "--output", "{output}", "--sleep", "1"]
        timeout_results = root / "timeout-results"
        run_one(child_run, limit_case, timeout_template, timeout_results, 0.2, child_environment,
                "external-sandbox", plan["suite_sha256"], contexts["baseline"],
                run_context_digest(timeout_template, child_environment, 0.2, "external-sandbox", contexts["baseline"]))
        timeout_receipt = read_json(timeout_results / child_run["blind_id"] / "receipt.json")
        require(timeout_receipt["timed_out"] is True and timeout_receipt["output_valid"] is False
                and timeout_receipt["duration_seconds"] >= 0.2, "main subprocess deadline was not enforced")

        sample = plan["runs"][0]
        receipt_path = results / sample["blind_id"] / "receipt.json"
        original_receipt = read_json(receipt_path)
        stale_receipt = {**original_receipt, "suite_sha256": "0" * 64}
        write_json(receipt_path, stale_receipt)
        stale_summary = build_score(mini_suite, plan, results)
        stale_score = stale_summary["variants"][sample["variant"]]
        require(stale_score["valid_outputs"] == summary["variants"][sample["variant"]]["valid_outputs"] - 1,
                "stale receipt was accepted")
        require(not stale_summary["release_gate"]["checks"]["all_outputs_valid"],
                "release gate accepted an invalid output")
        forged_receipt = dict(original_receipt)
        forged_receipt.pop("exit_code")
        write_json(receipt_path, forged_receipt)
        require(not load_artifact(results, sample["blind_id"])[2], "forged receipt was accepted")
        write_json(receipt_path, original_receipt)
        if previous_context_env is None:
            os.environ.pop(context_env, None)
        else:
            os.environ[context_env] = previous_context_env

    tampered = json.loads(json.dumps(mini_suite))
    tampered["cases"][0]["truth"]["required_edges"]["entry"][0]["end"] = 99
    try:
        validate_suite(tampered)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid truth anchor was accepted")
    unsafe_plan = json.loads(json.dumps(plan))
    unsafe_plan["runs"][0]["blind_id"] = "../outside"
    try:
        validate_plan(unsafe_plan, mini_suite)
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe blind id was accepted")
    print(f"self-test: ok ({default_report['cases']} cases, {default_report['pairs']} pairs; blind run and deterministic score verified)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run the deterministic end-to-end self-test")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate", help="validate a benchmark suite")
    validate_parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)

    plan_parser = subparsers.add_parser("plan", help="create a deterministic randomized paired plan")
    plan_parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    plan_parser.add_argument("--out", type=Path, required=True)
    plan_parser.add_argument("--repeats", type=int, default=3)
    plan_parser.add_argument("--seed", type=int, default=20260724)

    run_parser = subparsers.add_parser("run", help="execute every blind run from a plan")
    run_parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    run_parser.add_argument("--plan", type=Path, required=True)
    run_parser.add_argument("--results", type=Path, required=True)
    run_parser.add_argument("--baseline-command", required=True, help="JSON argv using {workspace},{prompt},{output},{schema},{blind_id}")
    run_parser.add_argument("--treatment-command", required=True, help="JSON argv using {workspace},{prompt},{output},{schema},{blind_id}")
    context_help = "JSON with client, model, reasoning, executor, network, token_budget, and profile/skill/tools SHA-256"
    run_parser.add_argument("--baseline-context", type=Path, required=True, help="frozen baseline " + context_help)
    run_parser.add_argument("--treatment-context", type=Path, required=True, help="frozen treatment " + context_help)
    run_parser.add_argument("--timeout", type=float, default=1800)
    run_parser.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                            help="forward one named host variable; only names enter receipts")
    run_parser.add_argument("--isolation", choices=("workspace-only", "external-sandbox"), default="workspace-only",
                            help="declare whether an external OS/container sandbox confines the command")
    run_parser.add_argument("--overwrite", action="store_true")

    record_parser = subparsers.add_parser("record", help="record a result produced by an external runner")
    record_parser.add_argument("--plan", type=Path, required=True)
    record_parser.add_argument("--results", type=Path, required=True)
    record_parser.add_argument("--blind-id", required=True)
    record_parser.add_argument("--output", type=Path, required=True)
    record_parser.add_argument("--receipt", type=Path, required=True)

    score_parser = subparsers.add_parser("score", help="score recorded blind results")
    score_parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    score_parser.add_argument("--plan", type=Path, required=True)
    score_parser.add_argument("--results", type=Path, required=True)
    score_parser.add_argument("--out", type=Path)

    subparsers.add_parser("self-test", help="run the deterministic end-to-end self-test")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.self_test or args.command == "self-test":
            self_test()
            return 0
        if args.command == "validate":
            _, report = load_suite(args.suite)
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.command == "plan":
            suite, _ = load_suite(args.suite)
            plan = build_plan(suite, args.repeats, args.seed)
            write_json(args.out, plan)
            print(f"plan: {len(plan['runs'])} blind runs -> {args.out}")
            return 0
        if args.command == "run":
            suite, _ = load_suite(args.suite)
            plan = read_json(args.plan)
            run_plan(
                suite,
                plan,
                args.results,
                parse_command(args.baseline_command),
                parse_command(args.treatment_command),
                args.timeout,
                args.overwrite,
                args.pass_env,
                args.isolation,
                {
                    "baseline": read_json(args.baseline_context),
                    "treatment": read_json(args.treatment_context),
                },
            )
            return 0
        if args.command == "record":
            plan = read_json(args.plan)
            record_result(plan, args.results, args.blind_id, args.output, args.receipt)
            print(f"recorded: {args.blind_id}")
            return 0
        if args.command == "score":
            suite, _ = load_suite(args.suite)
            plan = read_json(args.plan)
            summary = build_score(suite, plan, args.results)
            if args.out:
                write_json(args.out, summary)
            print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        parser.print_help()
        return 2
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

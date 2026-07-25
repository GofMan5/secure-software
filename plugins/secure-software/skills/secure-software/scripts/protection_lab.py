#!/usr/bin/env python3
"""Compare baseline and protected artifacts with bounded, reproducible release gates."""

from __future__ import annotations

import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
import platform
import stat
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

import evidence_adapter as evidence

LAB_VERSION = "1.0"
MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CANARIES = 100
MAX_CANARY_LENGTH = 512
MAX_HIT_LOCATIONS = 200
ZIP_SUFFIXES = {".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".nupkg", ".ipa"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return bool(left.st_ino and right.st_ino and (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino))


@contextlib.contextmanager
def open_regular(path: Path) -> Iterator[tuple[Any, os.stat_result]]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        linked = path.lstat()
        attributes = getattr(linked, "st_file_attributes", 0)
        require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(linked.st_mode)
                and not attributes & 0x400 and same_file(opened, linked),
                f"file changed or became a symlink before inspection: {path}")
        try:
            yield handle, opened
        finally:
            after = os.fstat(handle.fileno())
            linked_after = path.lstat()
            after_attributes = getattr(linked_after, "st_file_attributes", 0)
            require(stat.S_ISREG(linked_after.st_mode) and not after_attributes & 0x400
                    and same_file(opened, after) and same_file(after, linked_after)
                    and (opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
                    f"file changed during inspection: {path}")


@contextlib.contextmanager
def open_regular_at(directory_fd: int, name: str, display_path: Path) -> Iterator[tuple[Any, os.stat_result]]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(linked.st_mode) and same_file(opened, linked),
                f"file changed or became a symlink before inspection: {display_path}")
        try:
            yield handle, opened
        finally:
            after = os.fstat(handle.fileno())
            linked_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(stat.S_ISREG(linked_after.st_mode) and same_file(opened, after)
                    and same_file(after, linked_after)
                    and (opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
                    f"file changed during inspection: {display_path}")


def digest_and_sample(handle: Any, sample_bytes: int) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    sample = bytearray()
    handle.seek(0)
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
        if len(sample) < sample_bytes:
            sample.extend(chunk[:sample_bytes - len(sample)])
    return digest.hexdigest(), bytes(sample)


def directory_state(path: Path) -> os.stat_result:
    linked = path.lstat()
    attributes = getattr(linked, "st_file_attributes", 0)
    require(stat.S_ISDIR(linked.st_mode) and not attributes & 0x400,
            f"directory changed or became a symlink: {path}")
    return linked


def read_manifest(path: Path) -> tuple[dict[str, Any], str]:
    require(path.is_file(), f"manifest not found: {path}")
    require(path.stat().st_size <= MAX_MANIFEST_BYTES, f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    raw = path.read_bytes()
    data = json.loads(raw)
    require(isinstance(data, dict) and type(data.get("schema_version")) is int
            and data["schema_version"] == 1, "manifest schema_version must be integer 1")
    allowed = {"schema_version", "name", "canaries", "thresholds", "gates", "notes"}
    require(set(data) <= allowed, f"unknown manifest fields: {sorted(set(data) - allowed)}")
    require(isinstance(data.get("name", "protection-lab"), str), "manifest name must be a string")
    return data, hashlib.sha256(raw).hexdigest()


def parse_canaries(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    require(isinstance(value, list) and len(value) <= MAX_CANARIES, f"canaries must contain at most {MAX_CANARIES} strings")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        require(isinstance(item, str) and item, "each canary must be a non-empty string")
        require(len(item) <= MAX_CANARY_LENGTH, f"canary exceeds {MAX_CANARY_LENGTH} characters")
        digest = hashlib.sha256(item.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        patterns = [("utf-8", item.encode("utf-8"))]
        wide = item.encode("utf-16le")
        if wide != patterns[0][1]:
            patterns.append(("utf-16le", wide))
        result.append({"id": digest, "sha256": digest, "patterns": patterns})
    return result


def safe_archive_name(name: str) -> bool:
    if not name or "\x00" in name or name.startswith(("/", "\\")):
        return False
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and ".." not in path.parts and not (path.parts and ":" in path.parts[0])


def extension_of(name: str) -> str:
    suffix = PurePosixPath(name.replace("\\", "/")).suffix.lower()
    return suffix if suffix else "<none>"


def count_canaries(data: bytes, location: str, canaries: list[dict[str, Any]],
                   totals: dict[str, int], locations: list[dict[str, Any]]) -> None:
    for canary in canaries:
        count = 0
        encodings: list[str] = []
        for encoding, pattern in canary["patterns"]:
            hits = data.count(pattern)
            if hits:
                count += hits
                encodings.append(encoding)
        if count:
            totals[canary["id"]] += count
            if len(locations) < MAX_HIT_LOCATIONS:
                locations.append({"canary_id": canary["id"], "path": location, "count": count,
                                  "encodings": encodings})


def source_map_observation(name: str, data: bytes) -> dict[str, Any] | None:
    if not name.lower().endswith(".map"):
        return None
    observation: dict[str, Any] = {"path": name, "parsed": False, "sources": None, "has_sources_content": False}
    try:
        value = json.loads(data.decode("utf-8"))
        if isinstance(value, dict):
            sources = value.get("sources")
            contents = value.get("sourcesContent")
            observation.update(
                parsed=True,
                sources=len(sources) if isinstance(sources, list) else None,
                has_sources_content=isinstance(contents, list) and any(item not in (None, "") for item in contents),
            )
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return observation


def blank_inventory(role: str, path: Path) -> dict[str, Any]:
    return {
        "role": role,
        "path": str(path),
        "kind": None,
        "sha256": None,
        "digest_scope": "full-artifact",
        "size_bytes": 0,
        "files": 0,
        "symlinks_skipped": 0,
        "inventory_truncated": False,
        "content_scan_truncated": False,
        "extensions": {},
        "source_maps": {"count": 0, "with_sources_content": 0, "items": []},
        "canaries": {"total_hits": 0, "by_id": {}, "locations": [], "locations_truncated": False},
        "binary": None,
        "errors": [],
    }


def finalize_inventory(result: dict[str, Any], extension_counts: collections.Counter[str],
                       canaries: list[dict[str, Any]], totals: dict[str, int],
                       locations: list[dict[str, Any]], source_maps: list[dict[str, Any]]) -> dict[str, Any]:
    result["extensions"] = dict(sorted(extension_counts.items()))
    result["source_maps"] = {
        "count": len(source_maps),
        "with_sources_content": sum(1 for item in source_maps if item["has_sources_content"]),
        "items": source_maps[:100],
        "truncated": len(source_maps) > 100,
    }
    result["canaries"] = {
        "total_hits": sum(totals.values()),
        "by_id": {item["id"]: totals.get(item["id"], 0) for item in canaries},
        "locations": locations,
        "locations_truncated": len(locations) >= MAX_HIT_LOCATIONS,
    }
    return result


def inspect_file(role: str, path: Path, canaries: list[dict[str, Any]], max_file_bytes: int) -> dict[str, Any]:
    result = blank_inventory(role, path)
    extension_counts: collections.Counter[str] = collections.Counter({extension_of(path.name): 1})
    totals: dict[str, int] = collections.defaultdict(int)
    locations: list[dict[str, Any]] = []
    source_maps: list[dict[str, Any]] = []
    with open_regular(path) as (handle, opened):
        file_hash, data = digest_and_sample(handle, max_file_bytes)
        result.update(kind="file", sha256=file_hash, size_bytes=opened.st_size, files=1)
        count_canaries(data, path.name, canaries, totals, locations)
        source_map = source_map_observation(path.name, data)
        if source_map:
            source_maps.append(source_map)
        if opened.st_size > len(data):
            result["content_scan_truncated"] = True
        metadata, strings = evidence.binary_metadata_stream(
            handle, opened.st_size, min(max_file_bytes, 8 * 1024 * 1024), 4, 200
        )
        holder = {"runs": [], "observations": [strings]}
        evidence.apply_disclosure_policy(holder, False, False)
        result["binary"] = {"metadata": metadata, "strings": holder["observations"][0]}
    return finalize_inventory(result, extension_counts, canaries, totals, locations, source_maps)


def inspect_directory_fd(role: str, path: Path, canaries: list[dict[str, Any]], max_files: int,
                         max_file_bytes: int) -> dict[str, Any]:
    result = blank_inventory(role, path)
    result["kind"] = "directory"
    digest = hashlib.sha256()
    extension_counts: collections.Counter[str] = collections.Counter()
    totals: dict[str, int] = collections.defaultdict(int)
    locations: list[dict[str, Any]] = []
    source_maps: list[dict[str, Any]] = []
    files = 0
    stopped = False
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(path, flags)
    root_opened = os.fstat(root_fd)
    root_linked = path.lstat()
    require(stat.S_ISDIR(root_opened.st_mode) and stat.S_ISDIR(root_linked.st_mode)
            and same_file(root_opened, root_linked), f"directory changed before inspection: {path}")

    def record_walk_error(error: OSError) -> None:
        result["errors"].append(f"walk: {type(error).__name__}: {error}")

    try:
        for current, directory_names, file_names, directory_fd in os.fwalk(
            ".", topdown=True, onerror=record_walk_error, follow_symlinks=False, dir_fd=root_fd
        ):
            kept_directories: list[str] = []
            for name in sorted(directory_names):
                relative = (PurePosixPath(current) / name).as_posix().removeprefix("./")
                try:
                    linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    attributes = getattr(linked, "st_file_attributes", 0)
                    if stat.S_ISLNK(linked.st_mode) or attributes & 0x400:
                        result["symlinks_skipped"] += 1
                    elif stat.S_ISDIR(linked.st_mode):
                        kept_directories.append(name)
                    else:
                        result["errors"].append(f"{relative}: unsupported directory entry")
                except OSError as error:
                    result["errors"].append(f"{relative}: {type(error).__name__}: {error}")
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                relative = (PurePosixPath(current) / name).as_posix().removeprefix("./")
                try:
                    linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    attributes = getattr(linked, "st_file_attributes", 0)
                    if stat.S_ISLNK(linked.st_mode) or attributes & 0x400:
                        result["symlinks_skipped"] += 1
                        continue
                    if not stat.S_ISREG(linked.st_mode):
                        result["errors"].append(f"{relative}: unsupported file entry")
                        continue
                    if files >= max_files:
                        result["inventory_truncated"] = True
                        result["digest_scope"] = "bounded-inventory"
                        directory_names.clear()
                        stopped = True
                        break
                    with open_regular_at(directory_fd, name, path / Path(relative)) as (handle, opened):
                        file_hash, data = digest_and_sample(handle, max_file_bytes)
                        size = opened.st_size
                        digest.update(relative.encode("utf-8") + b"\0" + str(size).encode("ascii") + b"\0"
                                      + file_hash.encode("ascii") + b"\n")
                        result["size_bytes"] += size
                        extension_counts[extension_of(relative)] += 1
                        count_canaries(data, relative, canaries, totals, locations)
                        source_map = source_map_observation(relative, data)
                        if source_map:
                            source_maps.append(source_map)
                        if size > len(data):
                            result["content_scan_truncated"] = True
                        files += 1
                except (OSError, ValueError) as error:
                    result["errors"].append(f"{relative}: {type(error).__name__}: {error}")
            if stopped:
                break
    finally:
        try:
            root_after = path.lstat()
            require(stat.S_ISDIR(root_after.st_mode) and same_file(root_opened, root_after),
                    f"directory changed during inspection: {path}")
        finally:
            os.close(root_fd)
    result["files"] = files
    result["sha256"] = digest.hexdigest()
    return finalize_inventory(result, extension_counts, canaries, totals, locations, source_maps)


def inspect_directory(role: str, path: Path, canaries: list[dict[str, Any]], max_files: int,
                      max_file_bytes: int) -> dict[str, Any]:
    if hasattr(os, "fwalk") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
        return inspect_directory_fd(role, path, canaries, max_files, max_file_bytes)
    root_state = directory_state(path)
    result = blank_inventory(role, path)
    result["kind"] = "directory"
    digest = hashlib.sha256()
    extension_counts: collections.Counter[str] = collections.Counter()
    totals: dict[str, int] = collections.defaultdict(int)
    locations: list[dict[str, Any]] = []
    source_maps: list[dict[str, Any]] = []
    files = 0
    selected: list[Path] = []
    stack = [path]
    while stack and len(selected) <= max_files:
        current = stack.pop()
        try:
            require(same_file(root_state, directory_state(path)), f"root directory changed: {path}")
            current_state = directory_state(current)
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
            require(same_file(current_state, directory_state(current)), f"directory changed during listing: {current}")
            require(same_file(root_state, directory_state(path)), f"root directory changed: {path}")
        except (OSError, ValueError) as error:
            relative = current.relative_to(path).as_posix() or "."
            result["errors"].append(f"{relative}: {type(error).__name__}: {error}")
            continue
        directories: list[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            try:
                attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
                if entry.is_symlink() or attributes & 0x400:  # Windows FILE_ATTRIBUTE_REPARSE_POINT
                    result["symlinks_skipped"] += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    directories.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    selected.append(entry_path)
                    if len(selected) > max_files:
                        break
            except OSError as error:
                relative = entry_path.relative_to(path).as_posix()
                result["errors"].append(f"{relative}: {type(error).__name__}: {error}")
        stack.extend(reversed(directories))
    if len(selected) > max_files or stack:
        result["inventory_truncated"] = True
        result["digest_scope"] = "bounded-inventory"
    for item in sorted(selected[:max_files], key=lambda value: value.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix()
        files += 1
        try:
            with open_regular(item) as (handle, opened):
                file_hash, data = digest_and_sample(handle, max_file_bytes)
                size = opened.st_size
                digest.update(relative.encode("utf-8") + b"\0" + str(size).encode("ascii") + b"\0"
                              + file_hash.encode("ascii") + b"\n")
                result["size_bytes"] += size
                extension_counts[extension_of(relative)] += 1
                count_canaries(data, relative, canaries, totals, locations)
                source_map = source_map_observation(relative, data)
                if source_map:
                    source_maps.append(source_map)
                if size > len(data):
                    result["content_scan_truncated"] = True
        except (OSError, ValueError) as error:
            result["errors"].append(f"{relative}: {type(error).__name__}: {error}")
    result["files"] = files
    result["sha256"] = digest.hexdigest()
    require(same_file(root_state, directory_state(path)), f"root directory changed during inspection: {path}")
    return finalize_inventory(result, extension_counts, canaries, totals, locations, source_maps)


def inspect_zip(role: str, path: Path, canaries: list[dict[str, Any]], max_files: int,
                max_file_bytes: int) -> dict[str, Any]:
    result = blank_inventory(role, path)
    extension_counts: collections.Counter[str] = collections.Counter()
    totals: dict[str, int] = collections.defaultdict(int)
    locations: list[dict[str, Any]] = []
    source_maps: list[dict[str, Any]] = []
    try:
        with open_regular(path) as (handle, opened):
            file_hash, _ = digest_and_sample(handle, 0)
            result.update(kind="zip", sha256=file_hash, size_bytes=opened.st_size)
            handle.seek(0)
            with zipfile.ZipFile(handle) as archive:
                members = sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename)
                result["files"] = min(len(members), max_files)
                if len(members) > max_files:
                    result["inventory_truncated"] = True
                for member in members[:max_files]:
                    if not safe_archive_name(member.filename):
                        result["errors"].append(f"unsafe archive member: {member.filename!r}")
                        continue
                    extension_counts[extension_of(member.filename)] += 1
                    try:
                        with archive.open(member) as member_handle:
                            data = member_handle.read(max_file_bytes + 1)
                        if len(data) > max_file_bytes:
                            data = data[:max_file_bytes]
                            result["content_scan_truncated"] = True
                        count_canaries(data, member.filename, canaries, totals, locations)
                        source_map = source_map_observation(member.filename, data)
                        if source_map:
                            source_maps.append(source_map)
                    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                        result["errors"].append(f"{member.filename}: {type(error).__name__}: {error}")
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        result["errors"].append(f"BadZipFile: {error}")
    return finalize_inventory(result, extension_counts, canaries, totals, locations, source_maps)


def inspect_artifact(role: str, raw_path: Path, canaries: list[dict[str, Any]], max_files: int,
                     max_file_bytes: int) -> dict[str, Any]:
    path = Path(os.path.abspath(raw_path))
    linked = path.lstat()
    attributes = getattr(linked, "st_file_attributes", 0)
    if stat.S_ISLNK(linked.st_mode) or attributes & 0x400:
        raise ValueError(f"artifact must not be a symlink: {path}")
    if stat.S_ISDIR(linked.st_mode):
        return inspect_directory(role, path, canaries, max_files, max_file_bytes)
    require(stat.S_ISREG(linked.st_mode), f"artifact is not a file or directory: {path}")
    with open_regular(path) as (handle, _opened):
        is_zip = zipfile.is_zipfile(handle)
    if path.suffix.lower() in ZIP_SUFFIXES or is_zip:
        return inspect_zip(role, path, canaries, max_files, max_file_bytes)
    return inspect_file(role, path, canaries, max_file_bytes)


def validate_thresholds(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    require(isinstance(value, dict), "thresholds must be an object")
    allowed = {
        "max_size_growth_percent", "max_protected_canary_hits", "min_canary_reduction",
        "max_source_maps_with_content", "require_protected_digest_change",
    }
    require(set(value) <= allowed, f"unknown thresholds: {sorted(set(value) - allowed)}")
    for key in ("max_size_growth_percent",):
        if key in value:
            require(type(value[key]) in (int, float) and math.isfinite(value[key]), f"{key} must be finite")
    for key in ("max_protected_canary_hits", "min_canary_reduction", "max_source_maps_with_content"):
        if key in value:
            require(type(value[key]) is int and value[key] >= 0, f"{key} must be a non-negative integer")
    if "require_protected_digest_change" in value:
        require(isinstance(value["require_protected_digest_change"], bool), "require_protected_digest_change must be boolean")
    return value


def validate_manifest_contract(canaries: list[dict[str, Any]], thresholds: dict[str, Any]) -> None:
    if {"max_protected_canary_hits", "min_canary_reduction"} & set(thresholds):
        require(bool(canaries), "canary thresholds require at least one non-empty canary")


def replace_placeholders(value: str, role: str, artifact_path: Path) -> str:
    return (value.replace("{artifact}", str(artifact_path))
                 .replace("{artifact_dir}", str(artifact_path if artifact_path.is_dir() else artifact_path.parent))
                 .replace("{role}", role))


def validate_gates(value: Any, roles: dict[str, Path]) -> list[dict[str, Any]]:
    if value is None:
        return []
    require(isinstance(value, list) and len(value) <= 100, "gates must be a list of at most 100 entries")
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    for gate in value:
        require(isinstance(gate, dict), "each gate must be an object")
        allowed = {"id", "argv", "roles", "cwd", "mandatory", "expect_exit_codes", "max_duration_ms",
                   "require_equal_stdout", "require_equal_stderr", "tool"}
        require(set(gate) <= allowed, f"unknown gate fields: {sorted(set(gate) - allowed)}")
        gate_id = gate.get("id")
        argv = gate.get("argv")
        selected_roles = gate.get("roles", ["protected"])
        require(isinstance(gate_id, str) and gate_id and gate_id not in ids, "gate id must be unique and non-empty")
        ids.add(gate_id)
        require(isinstance(argv, list) and argv and all(isinstance(item, str) and item for item in argv),
                f"gate {gate_id} argv must be a non-empty string array")
        require(isinstance(selected_roles, list) and selected_roles and all(role in roles for role in selected_roles),
                f"gate {gate_id} roles must select available artifacts")
        require(len(selected_roles) == len(set(selected_roles)), f"gate {gate_id} roles must be unique")
        mandatory = gate.get("mandatory", True)
        require(isinstance(mandatory, bool), f"gate {gate_id} mandatory must be boolean")
        exit_codes = gate.get("expect_exit_codes", [0])
        require(isinstance(exit_codes, list) and exit_codes and all(type(code) is int for code in exit_codes),
                f"gate {gate_id} expect_exit_codes must be an integer array")
        max_duration = gate.get("max_duration_ms")
        require(max_duration is None or type(max_duration) is int and max_duration > 0,
                f"gate {gate_id} max_duration_ms must be a positive integer")
        for key in ("require_equal_stdout", "require_equal_stderr"):
            require(key not in gate or isinstance(gate[key], bool), f"gate {gate_id} {key} must be boolean")
        require(not (gate.get("require_equal_stdout") or gate.get("require_equal_stderr"))
                or set(selected_roles) >= {"baseline", "protected"},
                f"gate {gate_id} equality checks require baseline and protected roles")
        result.append(dict(gate, roles=selected_roles, mandatory=mandatory, expect_exit_codes=exit_codes))
    return result


def run_gates(gates: list[dict[str, Any]], roles: dict[str, Path], manifest_dir: Path,
              env: dict[str, str], secrets: list[str], timeout: float, capture_bytes: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    by_gate: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for gate in gates:
        for role in gate["roles"]:
            artifact_path = roles[role]
            argv = [replace_placeholders(item, role, artifact_path) for item in gate["argv"]]
            cwd_value = replace_placeholders(str(gate.get("cwd", manifest_dir)), role, artifact_path)
            cwd = Path(cwd_value)
            if not cwd.is_absolute():
                cwd = manifest_dir / cwd
            entry: dict[str, Any] = {
                "id": gate["id"], "role": role, "mandatory": gate["mandatory"],
                "expected_exit_codes": gate["expect_exit_codes"], "status": None,
            }
            try:
                require(cwd.resolve(strict=True).is_dir(), f"gate cwd is not a directory: {cwd}")
                run = evidence.execute(str(gate.get("tool") or Path(argv[0]).name), argv, cwd.resolve(), env,
                                       timeout, capture_bytes, secrets)
                entry["run"] = run
                passed = not run["timed_out"] and run["exit_code"] in gate["expect_exit_codes"]
                if gate.get("max_duration_ms") is not None:
                    passed = passed and run["duration_ms"] <= gate["max_duration_ms"]
                entry["status"] = "passed" if passed else "failed"
            except (OSError, ValueError) as error:
                entry.update(status="unavailable", error=f"{type(error).__name__}: {error}")
            results.append(entry)
            by_gate[gate["id"]].append(entry)
    for gate in gates:
        entries = by_gate[gate["id"]]
        indexed = {entry["role"]: entry for entry in entries}
        if set(indexed) >= {"baseline", "protected"} and all("run" in indexed[role] for role in ("baseline", "protected")):
            for stream, key in (("stdout", "require_equal_stdout"), ("stderr", "require_equal_stderr")):
                if gate.get(key):
                    equal = indexed["baseline"]["run"][stream]["sha256"] == indexed["protected"]["run"][stream]["sha256"]
                    for entry in entries:
                        entry.setdefault("comparisons", {})[f"equal_{stream}"] = equal
                        if not equal and entry["status"] == "passed":
                            entry["status"] = "failed"
    return results


def bind_post_gate_artifacts(inventories: dict[str, dict[str, Any]], paths: dict[str, Path],
                             canaries: list[dict[str, Any]], max_files: int, max_file_bytes: int) -> None:
    for role, path in paths.items():
        original = inventories[role]
        try:
            final = inspect_artifact(role, path, canaries, max_files, max_file_bytes)
            original_digest = canonical_digest(original)
            final_digest = canonical_digest(final)
            original["post_gate"] = {
                "status": "verified", "sha256": final["sha256"], "size_bytes": final["size_bytes"],
                "files": final["files"], "inventory_sha256": final_digest,
                "matches_initial_inventory": final_digest == original_digest,
            }
            original["changed_during_gates"] = final_digest != original_digest
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            original["post_gate"] = {"status": "unavailable", "error": f"{type(error).__name__}: {error}"}
            original["changed_during_gates"] = True


def compare_artifacts(baseline: dict[str, Any], protected: dict[str, Any]) -> dict[str, Any]:
    base_size = baseline["size_bytes"]
    protected_size = protected["size_bytes"]
    growth = None if base_size == 0 else round((protected_size - base_size) * 100.0 / base_size, 4)
    base_hits = baseline["canaries"]["total_hits"]
    protected_hits = protected["canaries"]["total_hits"]
    return {
        "digest_changed": baseline["sha256"] != protected["sha256"],
        "size_delta_bytes": protected_size - base_size,
        "size_growth_percent": growth,
        "canary_hit_reduction": base_hits - protected_hits,
        "source_maps_with_content_delta": (
            protected["source_maps"]["with_sources_content"] - baseline["source_maps"]["with_sources_content"]
        ),
        "file_count_delta": protected["files"] - baseline["files"],
    }


def evaluate(thresholds: dict[str, Any], inventories: dict[str, dict[str, Any]], gates: list[dict[str, Any]],
             comparison: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    protected = inventories["protected"]
    inventory_complete = {
        role: not inventory["inventory_truncated"]
        for role, inventory in inventories.items()
    }
    content_complete = {
        role: inventory_complete[role] and not inventory["content_scan_truncated"]
              and not inventory["symlinks_skipped"] and not inventory["errors"]
        for role, inventory in inventories.items()
    }

    def add_check(name: str, selected: bool, passed: bool | None, actual: Any, expected: Any,
                  complete: bool = True) -> None:
        if selected:
            status = "deferred" if not complete else "passed" if passed else "failed"
            checks.append({"name": name, "status": status, "actual": actual,
                           "expected": expected})

    if "max_size_growth_percent" in thresholds:
        actual = comparison["size_growth_percent"]
        add_check("max_size_growth_percent", True, actual is not None and actual <= thresholds["max_size_growth_percent"],
                  actual, thresholds["max_size_growth_percent"],
                  inventory_complete["baseline"] and inventory_complete["protected"])
    if "max_protected_canary_hits" in thresholds:
        actual = protected["canaries"]["total_hits"]
        add_check("max_protected_canary_hits", True, actual <= thresholds["max_protected_canary_hits"],
                  actual, thresholds["max_protected_canary_hits"], content_complete["protected"])
    if "min_canary_reduction" in thresholds:
        actual = comparison["canary_hit_reduction"]
        add_check("min_canary_reduction", True, actual >= thresholds["min_canary_reduction"],
                  actual, thresholds["min_canary_reduction"],
                  content_complete["baseline"] and content_complete["protected"])
    if "max_source_maps_with_content" in thresholds:
        actual = protected["source_maps"]["with_sources_content"]
        add_check("max_source_maps_with_content", True, actual <= thresholds["max_source_maps_with_content"],
                  actual, thresholds["max_source_maps_with_content"], content_complete["protected"])
    if thresholds.get("require_protected_digest_change"):
        add_check("require_protected_digest_change", True, comparison["digest_changed"], comparison["digest_changed"],
                  True, inventory_complete["baseline"] and inventory_complete["protected"])

    mandatory = [gate for gate in gates if gate["mandatory"]]
    failed_gates = [gate for gate in mandatory if gate["status"] == "failed"]
    unavailable_gates = [gate for gate in mandatory if gate["status"] == "unavailable"]
    failed_checks = [check for check in checks if check["status"] == "failed"]
    deferred_checks = [check for check in checks if check["status"] == "deferred"]
    changed_roles = [role for role, inventory in inventories.items() if inventory.get("changed_during_gates")]
    coverage_gaps: list[str] = []
    complete_content_roles: set[str] = set()
    if "max_protected_canary_hits" in thresholds or "max_source_maps_with_content" in thresholds:
        complete_content_roles.add("protected")
    if "min_canary_reduction" in thresholds:
        complete_content_roles.update(("baseline", "protected"))
    for role, inventory in inventories.items():
        if inventory["inventory_truncated"]:
            coverage_gaps.append(f"{role} inventory was bounded")
        if inventory["content_scan_truncated"] and role in complete_content_roles:
            coverage_gaps.append(f"{role} content scan was bounded for a selected leakage threshold")
        if inventory["symlinks_skipped"]:
            coverage_gaps.append(f"{role} skipped {inventory['symlinks_skipped']} symlink or reparse-point entries")
        coverage_gaps.extend(f"{role}: {error}" for error in inventory["errors"])
    if failed_gates or failed_checks or changed_roles:
        decision = "reject"
    elif unavailable_gates or coverage_gaps or deferred_checks:
        decision = "deferred"
    elif not checks and not mandatory:
        decision = "deferred"
        coverage_gaps.append("no mandatory acceptance gate or threshold selected")
    else:
        decision = "ship"
    return {
        "decision": decision,
        "checks": checks,
        "failed_gate_ids": sorted({gate["id"] for gate in failed_gates}),
        "unavailable_gate_ids": sorted({gate["id"] for gate in unavailable_gates}),
        "deferred_check_ids": [check["name"] for check in deferred_checks],
        "changed_artifact_roles": changed_roles,
        "coverage_gaps": coverage_gaps,
    }


def apply_gate_disclosure_policy(runs: list[dict[str, Any]], include_previews: bool) -> None:
    if include_previews:
        return
    for gate in runs:
        run = gate.get("run")
        if not isinstance(run, dict):
            continue
        for name in ("stdout", "stderr"):
            stream = run.get(name)
            if isinstance(stream, dict):
                stream["preview"] = evidence.OMITTED_PREVIEW if stream.get("bytes") else ""


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    started_at = utc_now()
    manifest_path = args.manifest.resolve(strict=True)
    manifest, manifest_sha256 = read_manifest(manifest_path)
    canaries = parse_canaries(manifest.get("canaries"))
    thresholds = validate_thresholds(manifest.get("thresholds"))
    validate_manifest_contract(canaries, thresholds)
    raw_paths: dict[str, Path] = {
        "baseline": args.baseline,
        "protected": args.protected,
    }
    if args.reference is not None:
        raw_paths["reference"] = args.reference
    overrides = evidence.parse_env(args.env)
    env = dict(os.environ, **overrides)
    secrets = evidence.secret_values(overrides)
    inventories = {
        role: inspect_artifact(role, path, canaries, args.max_files, args.max_file_bytes)
        for role, path in raw_paths.items()
    }
    paths = {role: Path(inventory["path"]) for role, inventory in inventories.items()}
    gates = validate_gates(manifest.get("gates"), paths)
    evidence.validate_run_budget(sum(len(gate["roles"]) for gate in gates), args.timeout, args.max_output_bytes)
    comparison = compare_artifacts(inventories["baseline"], inventories["protected"])
    runs = run_gates(gates, paths, manifest_path.parent, env, secrets, args.timeout, args.max_output_bytes)
    bind_post_gate_artifacts(inventories, paths, canaries, args.max_files, args.max_file_bytes)
    result = evaluate(thresholds, inventories, runs, comparison)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "lab": {"name": "secure-software-protection-lab", "version": LAB_VERSION},
        "manifest": {"path": str(manifest_path), "sha256": manifest_sha256,
                     "name": manifest.get("name", "protection-lab")},
        "started_at": started_at,
        "finished_at": None,
        "duration_ms": None,
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "limits": {"max_files": args.max_files, "max_file_bytes": args.max_file_bytes,
                   "max_output_bytes": args.max_output_bytes, "timeout_seconds": args.timeout},
        "artifacts": list(inventories.values()),
        "comparison": comparison,
        "runs": runs,
        "result": result,
    }
    receipt["finished_at"] = utc_now()
    receipt["duration_ms"] = round((time.monotonic() - started) * 1000)
    receipt = evidence.redact_value(receipt, secrets)
    apply_gate_disclosure_policy(receipt["runs"], args.include_previews)
    receipt["receipt_sha256"] = canonical_digest(receipt)
    return receipt


def self_test() -> None:
    if not __debug__:
        raise RuntimeError("self-test requires assertions; run Python without -O")
    with tempfile.TemporaryDirectory(prefix="protection-lab-self-test-") as directory:
        root = Path(directory)
        baseline = root / "baseline"
        protected = root / "protected"
        baseline.mkdir()
        protected.mkdir()
        (baseline / "app.bin").write_bytes(b"MZ\0LICENSE_BRANCH\0ROUTE_CANARY")
        (protected / "app.bin").write_bytes(b"MZ\0protected")
        (baseline / "app.js.map").write_text(json.dumps({"sources": ["app.ts"], "sourcesContent": ["source"]}), encoding="utf-8")
        (protected / "app.js.map").write_text(json.dumps({"sources": ["app.ts"]}), encoding="utf-8")
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": 1,
            "name": "self-test",
            "canaries": ["LICENSE_BRANCH", "ROUTE_CANARY"],
            "thresholds": {
                "max_protected_canary_hits": 0,
                "min_canary_reduction": 2,
                "max_source_maps_with_content": 0,
                "require_protected_digest_change": True,
            },
            "gates": [{
                "id": "artifact-exists",
                "roles": ["baseline", "protected"],
                "argv": [sys.executable, "-c", "import pathlib,sys;print('ok');sys.exit(0 if pathlib.Path(sys.argv[1]).exists() else 2)",
                         "{artifact}"],
                "mandatory": True,
            }],
        }), encoding="utf-8")
        args = argparse.Namespace(
            manifest=manifest, baseline=baseline, protected=protected, reference=None,
            max_files=100, max_file_bytes=4096, timeout=5.0, max_output_bytes=4096,
            env=[], include_previews=False,
        )
        receipt = build_receipt(args)
        assert receipt["result"]["decision"] == "ship"
        assert receipt["comparison"]["canary_hit_reduction"] == 2
        assert receipt["artifacts"][0]["source_maps"]["with_sources_content"] == 1
        assert all(run["status"] == "passed" for run in receipt["runs"])
        assert all(run["run"]["stdout"]["preview"] == evidence.OMITTED_PREVIEW for run in receipt["runs"])
        leaking = root / "leaking"
        leaking.mkdir()
        (leaking / "app.bin").write_bytes(b"LICENSE_BRANCH")
        args.protected = leaking
        rejected = build_receipt(args)
        assert rejected["result"]["decision"] == "reject"
        archive = root / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("../outside.txt", "x")
            output.writestr("safe/app.js.map", json.dumps({"sourcesContent": ["source"]}))
        zipped = inspect_artifact("protected", archive, [], 10, 4096)
        assert zipped["kind"] == "zip" and zipped["errors"] and zipped["source_maps"]["with_sources_content"] == 1
        small = root / "small.bin"
        large = root / "large.bin"
        small.write_bytes(b"base")
        large.write_bytes(b"protected-data")
        small_inventory = inspect_artifact("baseline", small, [], 10, 4)
        large_inventory = inspect_artifact("protected", large, [], 10, 4)
        assert not large_inventory["inventory_truncated"] and large_inventory["content_scan_truncated"]
        bounded_inventories = {"baseline": small_inventory, "protected": large_inventory}
        bounded_comparison = compare_artifacts(small_inventory, large_inventory)
        assert evaluate({"require_protected_digest_change": True}, bounded_inventories, [],
                        bounded_comparison)["decision"] == "ship"
        assert evaluate({"max_protected_canary_hits": 0}, bounded_inventories, [],
                        bounded_comparison)["decision"] == "deferred"
        late_baseline = root / "late-baseline.bin"
        clean_protected = root / "clean-protected.bin"
        late_baseline.write_bytes(b"prefix-LATE_CANARY")
        clean_protected.write_bytes(b"prefix-clean")
        late_canary = parse_canaries(["LATE_CANARY"])
        partial = {
            "baseline": inspect_artifact("baseline", late_baseline, late_canary, 10, 4),
            "protected": inspect_artifact("protected", clean_protected, late_canary, 10, 4),
        }
        partial_result = evaluate({"min_canary_reduction": 1}, partial, [],
                                  compare_artifacts(partial["baseline"], partial["protected"]))
        assert partial_result["decision"] == "deferred" and partial_result["checks"][0]["status"] == "deferred"
        complete = {
            "baseline": inspect_artifact("baseline", late_baseline, late_canary, 10, 4096),
            "protected": inspect_artifact("protected", clean_protected, late_canary, 10, 4096),
        }
        assert evaluate({"min_canary_reduction": 1}, complete, [],
                        compare_artifacts(complete["baseline"], complete["protected"]))["decision"] == "ship"
        try:
            validate_manifest_contract([], {"max_protected_canary_hits": 0})
            raise AssertionError("canary threshold without canaries was accepted")
        except ValueError:
            pass
        for invalid_thresholds in ({"max_size_growth_percent": True}, {"max_protected_canary_hits": False}):
            try:
                validate_thresholds(invalid_thresholds)
                raise AssertionError("boolean numeric threshold was accepted")
            except ValueError:
                pass
        gate_template = {"id": "strict", "argv": [sys.executable, "-c", "pass"]}
        for invalid_gate in (
            dict(gate_template, roles=["protected", "protected"]),
            dict(gate_template, expect_exit_codes=[True]),
            dict(gate_template, max_duration_ms=True),
        ):
            try:
                validate_gates([invalid_gate], {"baseline": small, "protected": large})
                raise AssertionError("invalid gate schema was accepted")
            except ValueError:
                pass
        invalid_manifest = root / "invalid-manifest.json"
        invalid_manifest.write_text(json.dumps({"schema_version": True}), encoding="utf-8")
        try:
            read_manifest(invalid_manifest)
            raise AssertionError("boolean schema_version was accepted")
        except ValueError:
            pass
        stable_baseline = root / "stable-baseline.bin"
        mutable_protected = root / "mutable-protected.bin"
        stable_baseline.write_bytes(b"A")
        mutable_protected.write_bytes(b"B")
        mutation_inventories = {
            "baseline": inspect_artifact("baseline", stable_baseline, [], 10, 4096),
            "protected": inspect_artifact("protected", mutable_protected, [], 10, 4096),
        }
        mutation_comparison = compare_artifacts(mutation_inventories["baseline"],
                                                mutation_inventories["protected"])
        mutable_protected.write_bytes(b"C")
        bind_post_gate_artifacts(mutation_inventories,
                                 {"baseline": stable_baseline, "protected": mutable_protected}, [], 10, 4096)
        assert mutation_inventories["protected"]["changed_during_gates"]
        assert evaluate({"require_protected_digest_change": True}, mutation_inventories, [],
                        mutation_comparison)["decision"] == "reject"
        race_dir = root / "race"
        race_dir.mkdir()
        race_file = race_dir / "inside.bin"
        outside = root / "outside.bin"
        probe_link = root / "symlink-probe"
        race_file.write_bytes(b"inside")
        outside.write_bytes(b"OUTSIDE_CANARY")
        try:
            probe_link.symlink_to(outside)
            probe_link.unlink()
            if hasattr(os, "fwalk") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
                original_open_at = globals()["open_regular_at"]

                @contextlib.contextmanager
                def swapping_open_at(directory_fd: int, name: str,
                                     display_path: Path) -> Iterator[tuple[Any, os.stat_result]]:
                    if display_path == race_file and not display_path.is_symlink():
                        display_path.unlink()
                        display_path.symlink_to(outside)
                    with original_open_at(directory_fd, name, display_path) as opened:
                        yield opened

                globals()["open_regular_at"] = swapping_open_at
                try:
                    raced = inspect_directory("protected", race_dir, parse_canaries(["OUTSIDE_CANARY"]), 10, 4096)
                finally:
                    globals()["open_regular_at"] = original_open_at
            else:
                original_open = globals()["open_regular"]

                @contextlib.contextmanager
                def swapping_open(path: Path) -> Iterator[tuple[Any, os.stat_result]]:
                    if path == race_file and not path.is_symlink():
                        path.unlink()
                        path.symlink_to(outside)
                    with original_open(path) as opened:
                        yield opened

                globals()["open_regular"] = swapping_open
                try:
                    raced = inspect_directory("protected", race_dir, parse_canaries(["OUTSIDE_CANARY"]), 10, 4096)
                finally:
                    globals()["open_regular"] = original_open
            assert raced["canaries"]["total_hits"] == 0 and raced["errors"]
            if hasattr(os, "fwalk") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
                root_race = root / "root-race"
                moved_root = root / "root-race-original"
                outside_dir = root / "outside-dir"
                root_race.mkdir()
                outside_dir.mkdir()
                (root_race / "inside.bin").write_bytes(b"inside")
                (outside_dir / "outside.bin").write_bytes(b"OUTSIDE_CANARY")
                original_fwalk = os.fwalk

                def swapping_fwalk(*args: Any, **kwargs: Any) -> Any:
                    root_race.rename(moved_root)
                    root_race.symlink_to(outside_dir, target_is_directory=True)
                    return original_fwalk(*args, **kwargs)

                os.fwalk = swapping_fwalk
                try:
                    try:
                        inspect_directory("protected", root_race, parse_canaries(["OUTSIDE_CANARY"]), 10, 4096)
                        raise AssertionError("top-level directory swap was accepted")
                    except ValueError:
                        pass
                finally:
                    os.fwalk = original_fwalk
        except OSError:
            pass
        link = root / "artifact-link"
        try:
            link.symlink_to(protected, target_is_directory=True)
            try:
                inspect_artifact("protected", link, [], 10, 4096)
                raise AssertionError("top-level symlink artifact was accepted")
            except ValueError:
                pass
        except OSError:
            pass
        output = root / "receipt.json"
        evidence.write_receipt(output, receipt, False)
        try:
            evidence.write_receipt(output, rejected, False)
            raise AssertionError("existing receipt was overwritten")
        except FileExistsError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline inventory, gate, and decision checks")
    parser.add_argument("--manifest", type=Path, help="Gate manifest with schema_version 1")
    parser.add_argument("--baseline", type=Path, help="Normal release or unprotected artifact")
    parser.add_argument("--protected", type=Path, help="Protected artifact")
    parser.add_argument("--reference", type=Path, help="Optional debug/reference artifact")
    parser.add_argument("--output", type=Path, help="Atomic JSON receipt path")
    parser.add_argument("--force", action="store_true", help="Replace an existing receipt")
    parser.add_argument("--timeout", type=float, default=evidence.DEFAULT_TIMEOUT, help="Per gate timeout in seconds")
    parser.add_argument("--max-output-bytes", type=int, default=evidence.DEFAULT_CAPTURE_BYTES,
                        help="Captured bytes per gate stdout/stderr")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum inventoried files per artifact")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES,
                        help="Maximum bytes scanned per file or archive member")
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE",
                        help="Gate environment override; values are never recorded")
    parser.add_argument("--include-previews", action="store_true",
                        help="Include bounded redacted gate output previews")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("self-test: ok")
        return 0
    for name in ("manifest", "baseline", "protected", "output"):
        if getattr(args, name) is None:
            raise SystemExit(f"--{name} is required unless --self-test is selected")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise SystemExit("--timeout must be finite and greater than zero")
    if not 1 <= args.max_output_bytes <= evidence.MAX_CAPTURE_BYTES:
        raise SystemExit(f"--max-output-bytes must be 1..{evidence.MAX_CAPTURE_BYTES}")
    if not 1 <= args.max_files <= MAX_FILES:
        raise SystemExit(f"--max-files must be 1..{MAX_FILES}")
    if not 1 <= args.max_file_bytes <= MAX_FILE_BYTES:
        raise SystemExit(f"--max-file-bytes must be 1..{MAX_FILE_BYTES}")
    try:
        receipt = build_receipt(args)
        evidence.write_receipt(args.output, receipt, args.force)
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps({"output": str(args.output), "decision": receipt["result"]["decision"],
                      "receipt_sha256": receipt["receipt_sha256"]}, sort_keys=True))
    return 0 if receipt["result"]["decision"] == "ship" else 2


if __name__ == "__main__":
    raise SystemExit(main())

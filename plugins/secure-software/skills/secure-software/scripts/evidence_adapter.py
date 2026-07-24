#!/usr/bin/env python3
"""Collect bounded scanner, binary, and runtime evidence into one JSON receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ADAPTER_VERSION = "1.0"
DEFAULT_TIMEOUT = 120.0
DEFAULT_CAPTURE_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_OBSERVATIONS = 500
SECRET_NAME = re.compile(
    r"(?i)(?:token|secret|pass(?:word)?|api[_-]?key|auth|cookie|credential|connection[_-]?string|"
    r"(?:x[_-]?(?:amz|goog)[_-]?)?signature|sig|sas)"
)
SECRET_FLAGS = {
    "--token", "--secret", "--password", "--passwd", "--api-key", "--apikey",
    "--authorization", "--cookie", "--client-secret", "--access-key", "--private-key",
    "--access-token", "--github-token", "--secret-access-key", "--aws-secret-access-key",
    "--user", "--proxy-user", "-u", "-p",
}
REDACTED = "<redacted>"
OMITTED_PREVIEW = "<omitted: sensitive preview>"
SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|sk_live_[0-9A-Za-z]{16,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----", re.DOTALL),
)
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SAFE_HTTP_HEADERS = {
    "age", "allow", "cache-control", "content-length", "content-security-policy",
    "content-type", "date", "etag", "expires", "last-modified", "location", "server",
    "strict-transport-security", "vary", "via", "x-content-type-options", "x-frame-options",
    "x-request-id",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def bounded(value: Any, limit: int = 2_000) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "\\0")
    return text if len(text) <= limit else text[:limit] + "..."


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = ""
        if parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            if parsed.port:
                host += f":{parsed.port}"
        segments = []
        for segment in parsed.path.split("/"):
            decoded = unquote(segment)
            if SECRET_NAME.search(decoded) or any(pattern.search(decoded) for pattern in SECRET_VALUE_PATTERNS):
                segment = REDACTED
            segments.append(segment)
        query = [
            (REDACTED if SECRET_NAME.search(key) else key, REDACTED)
            for key, _item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, host, "/".join(segments), urlencode(query), ""))
    except (TypeError, ValueError):
        return "<redacted-url>"


def redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for value in argv:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        lower = value.lower()
        if lower in SECRET_FLAGS or value == "-H" or lower == "--header" or (
            lower.startswith("--") and "=" not in value and SECRET_NAME.search(value)
        ):
            redacted.append(value)
            hide_next = True
            continue
        if lower.startswith("--header="):
            redacted.append(value.split("=", 1)[0] + "=<redacted>")
            continue
        if value.startswith("-H") and len(value) > 2:
            redacted.append("-H<redacted>")
            continue
        if lower.startswith("-u") and len(value) > 2:
            redacted.append("-u<redacted>")
            continue
        if "=" in value:
            key, item = value.split("=", 1)
            if SECRET_NAME.search(key):
                redacted.append(f"{key}=<redacted>")
                continue
        redacted.append(redact_url(value) if "://" in value else value)
    return redacted


def secret_values(overrides: dict[str, str]) -> list[str]:
    values = [value for value in overrides.values() if value]
    values.extend(value for key, value in os.environ.items() if SECRET_NAME.search(key) and len(value) >= 4)
    return sorted(set(values), key=len, reverse=True)


def redact_text(text: str, secrets: list[str]) -> str:
    if text in {REDACTED, OMITTED_PREVIEW}:
        return text
    protected = re.split(f"({re.escape(REDACTED)}|{re.escape(OMITTED_PREVIEW)})", text)
    for index in range(0, len(protected), 2):
        part = protected[index]
        if any(value and len(value) < 4 and value in part for value in secrets):
            return OMITTED_PREVIEW
        for value in secrets:
            if value:
                part = part.replace(value, REDACTED)
        for pattern in SECRET_VALUE_PATTERNS:
            part = pattern.sub(REDACTED, part)
        protected[index] = part
    text = "".join(protected)
    text = re.sub(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+", rf"\1{REDACTED}", text)
    text = re.sub(
        r"(?i)([\"']?(?:token|secret|password|api[_-]?key|auth|cookie|credential|signature|sig)[\"']?\s*[:=]\s*)([\"'])(.*?)\2",
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(2)}",
        text,
    )
    text = re.sub(
        r"(?i)([\"']?(?:token|secret|password|api[_-]?key|auth|cookie|credential|signature|sig)[\"']?\s*[:=]\s*)[^\s,;\"']+",
        rf"\1{REDACTED}",
        text,
    )
    return text


def redact_value(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        return {key: redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, str):
        redacted = redact_text(value, secrets)
        return URL_IN_TEXT.sub(lambda match: redact_url(match.group()), redacted)
    return value


def parse_env(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError("--env requires NAME=VALUE")
        name, value = item.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"invalid environment name: {name}")
        result[name] = value
    return result


class Capture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()

    def read(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                self.total += len(chunk)
                self.digest.update(chunk)
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def receipt(self, secrets: list[str]) -> dict[str, Any]:
        truncated = self.total > len(self.data)
        preview = "<omitted: truncated stream>" if truncated else redact_text(
            bytes(self.data).decode("utf-8", errors="replace"), secrets
        )
        if len(preview.encode("utf-8")) > self.limit:
            preview = OMITTED_PREVIEW
        return {
            "bytes": self.total,
            "captured_bytes": len(self.data),
            "truncated": truncated,
            "sha256": self.digest.hexdigest(),
            "preview": preview,
        }


def stop_process(proc: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            taskkill = shutil.which("taskkill")
            if taskkill:
                subprocess.run([taskkill, "/PID", str(proc.pid), "/T", "/F"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            else:
                proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
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
                ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
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
                    thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
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
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(job)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_raw(argv: list[str], cwd: Path, env: dict[str, str], timeout: float, limit: int,
            secrets: list[str]) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    stdout = Capture(limit)
    stderr = Capture(limit)
    flags = (subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004) if os.name == "nt" else 0
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
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
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        proc.stdout.close()
        proc.stderr.close()
        raise OSError("unable to establish Windows process-tree containment")
    readers = [threading.Thread(target=stdout.read, args=(proc.stdout,), daemon=True),
               threading.Thread(target=stderr.read, args=(proc.stderr,), daemon=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    group_closed = False
    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        close_process_group(proc, job)
        group_closed = True
        try:
            exit_code = proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            stop_process(proc)
            exit_code = proc.wait(timeout=1)
    finally:
        if not group_closed:
            close_process_group(proc, job)
    deadline = started + timeout
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(reader.is_alive() for reader in readers):
        timed_out = True
        proc.stdout.close()
        proc.stderr.close()
        cleanup_deadline = time.monotonic() + 0.25
        for reader in readers:
            reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            raise OSError("subprocess capture threads did not stop")
    return {
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout.receipt(secrets),
        "stderr": stderr.receipt(secrets),
    }


def resolve_executable(name: str, cwd: Path, env: dict[str, str]) -> str:
    candidate = Path(name)
    has_directory = any(separator and separator in name for separator in (os.sep, os.altsep))
    if candidate.is_absolute() or has_directory:
        path = candidate if candidate.is_absolute() else cwd / candidate
        if path.is_file():
            return str(path.resolve())
        raise FileNotFoundError(f"tool not found: {name}")
    path = shutil.which(name, path=env.get("PATH"))
    if not path:
        raise FileNotFoundError(f"tool not found: {name}")
    return str(Path(path).resolve())


def probe_version(label: str, executable: str, cwd: Path, env: dict[str, str], secrets: list[str], timeout: float) -> str | None:
    args = ["-v"] if label == "rabin2" else (["/?"] if label == "dumpbin" else ["--version"])
    if label == "cargo-audit":
        args = ["--version"]
    elif label == "kubectl":
        args = ["version", "--client", "--output=json"]
    try:
        result = run_raw([executable, *args], cwd, env, timeout, 8 * 1024, secrets)
        text = (result["stdout"]["preview"] + "\n" + result["stderr"]["preview"]).strip()
        return bounded(text.splitlines()[0], 300) if text else None
    except (OSError, subprocess.SubprocessError):
        return None


def execute(label: str, argv: list[str], cwd: Path, env: dict[str, str], timeout: float,
            limit: int, secrets: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    executable = resolve_executable(argv[0], cwd, env)
    full_argv = [executable, *argv[1:]]
    version = probe_version(label, executable, cwd, env, secrets, min(5.0, timeout))
    remaining = max(0.001, timeout - (time.monotonic() - started))
    receipt = {
        "tool": {"name": label, "path": executable, "version": version},
        "argv": redact_argv(full_argv),
        "cwd": str(cwd),
        "environment_keys": sorted(key for key in env if key not in os.environ or env[key] != os.environ[key]),
    }
    receipt.update(run_raw(full_argv, cwd, env, remaining, limit, secrets))
    return receipt


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, role: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "role": role,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "sha256": sha256_file(path),
    }


def lead(source: str, identifier: Any = None, title: Any = None, severity: Any = None,
         location: Any = None, package_name: Any = None, url: Any = None) -> dict[str, Any]:
    item = {"type": "candidate_lead", "source": source}
    for key, value in (("id", identifier), ("title", title), ("severity", severity),
                       ("location", location), ("package", package_name), ("url", url)):
        if value not in (None, "", []):
            item[key] = bounded(value)
    return item


def sarif_observations(data: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for run in data.get("runs", []) if isinstance(data.get("runs"), list) else []:
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        source = bounded(driver.get("name"), 200) if isinstance(driver, dict) else "sarif"
        tools.append({"name": source or "sarif", "version": bounded(driver.get("version"), 200) if isinstance(driver, dict) else None})
        for result in run.get("results", []) if isinstance(run.get("results"), list) else []:
            if len(observations) >= limit or not isinstance(result, dict):
                break
            message = result.get("message", {})
            message = message.get("text") if isinstance(message, dict) else message
            location = None
            locations = result.get("locations")
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                artifact_location = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                location = artifact_location.get("uri") if isinstance(artifact_location, dict) else None
                if location and isinstance(region, dict) and region.get("startLine"):
                    location = f"{location}:{region['startLine']}"
            observations.append(lead(source or "sarif", result.get("ruleId"), message, result.get("level"), location))
    return observations, tools


def scanner_observations(label: str, raw: str, limit: int) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        if label == "govulncheck":
            data = []
            for line in raw.splitlines():
                if not line.strip().startswith("{"):
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            return []
    if isinstance(data, dict) and data.get("version") == "2.1.0" and isinstance(data.get("runs"), list):
        return sarif_observations(data, limit)[0]
    found: list[dict[str, Any]] = []

    def add(item: dict[str, Any]) -> None:
        if len(found) < limit and set(item) - {"type", "source"}:
            found.append(item)

    if label == "cargo-audit" and isinstance(data, dict):
        vulns = data.get("vulnerabilities", {})
        for item in vulns.get("list", []) if isinstance(vulns, dict) else []:
            if not isinstance(item, dict):
                continue
            advisory, package = item.get("advisory", {}), item.get("package", {})
            advisory = advisory if isinstance(advisory, dict) else {}
            package = package if isinstance(package, dict) else {}
            add(lead(label, advisory.get("id"), advisory.get("title"), advisory.get("cvss"),
                     package.get("source"), f"{package.get('name')}@{package.get('version')}", advisory.get("url")))
    elif label == "npm-audit" and isinstance(data, dict):
        vulns = data.get("vulnerabilities", {})
        for name, item in vulns.items() if isinstance(vulns, dict) else []:
            if not isinstance(item, dict):
                continue
            via = item.get("via", []) if isinstance(item, dict) else []
            detail = next((entry for entry in via if isinstance(entry, dict)), {})
            add(lead(label, detail.get("source"), detail.get("title") or name, item.get("severity"),
                     None, f"{name} {item.get('range', '')}".strip(), detail.get("url")))
    elif label == "pip-audit":
        packages = data.get("dependencies", []) if isinstance(data, dict) else data
        for package in packages if isinstance(packages, list) else []:
            if not isinstance(package, dict):
                continue
            package_id = f"{package.get('name')}@{package.get('version')}"
            for vuln in package.get("vulns", []) if isinstance(package.get("vulns"), list) else []:
                if isinstance(vuln, dict):
                    add(lead(label, vuln.get("id"), vuln.get("description") or vuln.get("id"),
                             None, None, package_id, vuln.get("url")))
    elif label == "govulncheck":
        messages = data if isinstance(data, list) else [data]
        for message in messages:
            finding = message.get("finding") if isinstance(message, dict) else None
            if not isinstance(finding, dict):
                continue
            trace = finding.get("trace") if isinstance(finding.get("trace"), list) else []
            frame = next((item for item in trace if isinstance(item, dict) and item.get("position")), {})
            position = frame.get("position") if isinstance(frame, dict) else None
            location = None
            if isinstance(position, dict) and position.get("filename"):
                location = f"{position['filename']}:{position.get('line', 0)}"
            package_name = frame.get("package") or frame.get("module") if isinstance(frame, dict) else None
            add(lead(label, finding.get("osv") or finding.get("id"), finding.get("osv") or finding.get("id"),
                     None, location, package_name))
    elif label == "trivy" and isinstance(data, dict):
        for result in data.get("Results", []) if isinstance(data.get("Results"), list) else []:
            if not isinstance(result, dict):
                continue
            target = result.get("Target")
            for vuln in result.get("Vulnerabilities", []) if isinstance(result.get("Vulnerabilities"), list) else []:
                if isinstance(vuln, dict):
                    add(lead(label, vuln.get("VulnerabilityID"), vuln.get("Title"), vuln.get("Severity"), target,
                             f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}", vuln.get("PrimaryURL")))
            for finding in result.get("Misconfigurations", []) if isinstance(result.get("Misconfigurations"), list) else []:
                if isinstance(finding, dict):
                    add(lead(label, finding.get("ID"), finding.get("Title") or finding.get("Message"),
                             finding.get("Severity"), target))
            for finding in result.get("Secrets", []) if isinstance(result.get("Secrets"), list) else []:
                if isinstance(finding, dict):
                    line = finding.get("StartLine")
                    add(lead(label, finding.get("RuleID"), finding.get("Title") or "potential secret",
                             finding.get("Severity"), f"{target}:{line}" if line else target))
    elif label == "detect-secrets" and isinstance(data, dict):
        results = data.get("results")
        for path, findings in results.items() if isinstance(results, dict) else []:
            for finding in findings if isinstance(findings, list) else []:
                if isinstance(finding, dict):
                    line = finding.get("line_number")
                    add(lead(label, finding.get("type"), finding.get("type") or "potential secret", None,
                             f"{path}:{line}" if line else path))
    elif label == "osv-scanner" and isinstance(data, dict):
        for result in data.get("results", []) if isinstance(data.get("results"), list) else []:
            if not isinstance(result, dict):
                continue
            for package in result.get("packages", []) if isinstance(result.get("packages"), list) else []:
                if not isinstance(package, dict):
                    continue
                identity = package.get("package") if isinstance(package.get("package"), dict) else {}
                package_id = f"{identity.get('name')}@{identity.get('version')}"
                for vuln in package.get("vulnerabilities", []) if isinstance(package.get("vulnerabilities"), list) else []:
                    if isinstance(vuln, dict):
                        add(lead(label, vuln.get("id"), vuln.get("summary") or vuln.get("details"),
                                 None, result.get("source"), package_id, vuln.get("database_specific", {}).get("url")
                                 if isinstance(vuln.get("database_specific"), dict) else None))
    elif label == "checkov" and isinstance(data, dict):
        results = data.get("results")
        failed = results.get("failed_checks", []) if isinstance(results, dict) else []
        for item in failed if isinstance(failed, list) else []:
            if isinstance(item, dict):
                add(lead(label, item.get("check_id"), item.get("check_name"), item.get("severity"),
                         item.get("file_path") or item.get("resource")))
    elif label == "semgrep" and isinstance(data, dict):
        for item in data.get("results", []) if isinstance(data.get("results"), list) else []:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra", {}) if isinstance(item.get("extra"), dict) else {}
            start = item.get("start", {}) if isinstance(item.get("start"), dict) else {}
            location = f"{item.get('path')}:{start.get('line')}" if start.get("line") else item.get("path")
            add(lead(label, item.get("check_id"), extra.get("message"), extra.get("severity"), location))
    elif label == "bandit" and isinstance(data, dict):
        for item in data.get("results", []) if isinstance(data.get("results"), list) else []:
            if isinstance(item, dict):
                add(lead(label, item.get("test_id"), item.get("issue_text"), item.get("issue_severity"),
                         f"{item.get('filename')}:{item.get('line_number')}"))
    else:
        candidates: list[Any] = []
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            for key in ("results", "findings", "issues", "Issues", "vulnerabilities", "matches"):
                value = data.get(key)
                if isinstance(value, list):
                    candidates.extend(value)
                elif isinstance(value, dict):
                    candidates.extend(value.values())
        for item in candidates:
            if not isinstance(item, dict):
                continue
            add(lead(label, item.get("id") or item.get("rule_id") or item.get("RuleID") or item.get("vulnerability_id"),
                     item.get("title") or item.get("message") or item.get("description") or item.get("rule_description"),
                     item.get("severity") or item.get("level"), item.get("path") or item.get("file") or item.get("target"),
                     item.get("package") or item.get("dependency"), item.get("url") or item.get("link")))
    return found[:limit]


def scanner_command(label: str, scope: Path) -> tuple[list[str], Path]:
    cwd = scope if scope.is_dir() else scope.parent
    if label == "cargo-audit":
        lock = scope / "Cargo.lock" if scope.is_dir() else scope
        return ["cargo-audit", "audit", "--json", "--file", str(lock)], cwd
    if label == "npm-audit":
        return ["npm", "audit", "--json", "--ignore-scripts"], cwd
    if label == "semgrep":
        return ["semgrep", "scan", "--json", "--metrics=off", "--config", "auto", str(scope)], cwd
    if label == "bandit":
        return ["bandit", "-r", str(scope), "-f", "json", "-q"], cwd
    if label == "trivy":
        return ["trivy", "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", str(scope)], cwd
    if label == "osv-scanner":
        return ["osv-scanner", "scan", "source", "--recursive", str(scope), "--format", "json"], cwd
    if label == "checkov":
        return ["checkov", "-d", str(scope), "-o", "json", "--quiet"], cwd
    if label == "tfsec":
        return ["tfsec", "--format", "json", str(scope)], cwd
    if label == "gosec":
        return ["gosec", "-fmt=json", "./..."], cwd
    if label == "govulncheck":
        return ["govulncheck", "-json", "./..."], cwd
    if label == "detect-secrets":
        return ["detect-secrets", "scan", "--all-files"], cwd
    if label == "pip-audit":
        base = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
        if scope.is_dir():
            requirements = scope / "requirements.txt"
            if requirements.is_file():
                return [*base, "-r", str(requirements)], cwd
            if (scope / "pylock.toml").is_file() or any(scope.glob("pylock.*.toml")):
                return [*base, "--locked", str(scope)], cwd
            if (scope / "pyproject.toml").is_file():
                return [*base, str(scope)], cwd
        elif scope.name == "pyproject.toml":
            return [*base, str(scope.parent)], scope.parent
        elif scope.name == "pylock.toml" or re.fullmatch(r"pylock\..+\.toml", scope.name):
            return [*base, "--locked", str(scope.parent)], scope.parent
        else:
            return [*base, "-r", str(scope)], cwd
        raise ValueError(f"no supported Python dependency file in scope: {scope}")
    raise ValueError(f"unknown scanner profile: {label}")


def auto_scanners(scope: Path) -> list[str]:
    if not scope.is_dir():
        return []
    selected: list[str] = []
    if (scope / "Cargo.lock").is_file() and shutil.which("cargo-audit"):
        selected.append("cargo-audit")
    if any((scope / name).is_file() for name in ("package-lock.json", "npm-shrinkwrap.json")) and shutil.which("npm"):
        selected.append("npm-audit")
    if (scope / "go.mod").is_file() and shutil.which("govulncheck"):
        selected.append("govulncheck")
    if shutil.which("pip-audit") and (
        (scope / "requirements.txt").is_file()
        or (scope / "pyproject.toml").is_file()
        or (scope / "pylock.toml").is_file()
        or any(scope.glob("pylock.*.toml"))
    ):
        selected.append("pip-audit")
    return selected


def binary_metadata(path: Path, string_bytes: int, string_min: int, string_limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    with path.open("rb") as handle:
        header = handle.read(4096)
        handle.seek(0)
        sample = handle.read(string_bytes)
    info: dict[str, Any] = {"type": "binary_metadata", "format": "unknown"}
    if header.startswith(b"MZ") and len(header) >= 64:
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        with path.open("rb") as handle:
            handle.seek(pe_offset)
            pe = handle.read(256)
        if pe.startswith(b"PE\0\0") and len(pe) >= 26:
            machine, sections, timestamp = struct.unpack_from("<HHI", pe, 4)
            info.update(format="PE", architecture={0x14C: "x86", 0x8664: "x86_64", 0x1C4: "arm", 0xAA64: "arm64"}.get(machine, hex(machine)),
                        sections=sections, timestamp=timestamp)
    elif header.startswith(b"\x7fELF") and len(header) >= 20:
        endian = "<" if header[5] == 1 else ">"
        machine = struct.unpack_from(endian + "H", header, 18)[0]
        info.update(format="ELF", bits=64 if header[4] == 2 else 32,
                    architecture={3: "x86", 40: "arm", 62: "x86_64", 183: "arm64", 243: "riscv"}.get(machine, str(machine)))
    elif header.startswith(b"\xca\xfe\xba\xbe") and len(header) >= 8:
        minor, major = struct.unpack_from(">HH", header, 4)
        if 45 <= major <= 100:
            info.update(format="Java class", class_version=major, minor_version=minor)
        else:
            info.update(format="Mach-O", container="fat", architectures=struct.unpack_from(">I", header, 4)[0])
    elif header[:4] in {b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"} and len(header) >= 8:
        endian = "<" if header[:4] in {b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"} else ">"
        info.update(format="Mach-O", container="fat64" if header[:4] in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"} else "fat",
                    architectures=struct.unpack_from(endian + "I", header, 4)[0])
    elif header[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        info.update(format="Mach-O", bits=64 if header[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"} else 32)
    pattern = re.compile(rb"[\x20-\x7e]{" + str(string_min).encode() + rb",}")
    wide = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(string_min).encode() + rb",}")
    values: list[dict[str, Any]] = []
    input_truncated = False
    for encoding, regex in (("ascii", pattern), ("utf-16le", wide)):
        for index, match in enumerate(regex.finditer(sample)):
            if index > string_limit:
                input_truncated = True
                break
            value = match.group().decode("utf-16le" if encoding == "utf-16le" else "ascii", errors="replace")
            values.append({"offset": match.start(), "encoding": encoding, "value": bounded(value, 500)})
    values.sort(key=lambda item: item["offset"])
    strings = {"type": "bounded_strings", "scanned_bytes": len(sample), "input_truncated": path.stat().st_size > len(sample),
               "limit": string_limit, "truncated": input_truncated or len(values) > string_limit, "values": values[:string_limit]}
    return info, strings


def binary_command(label: str, target: Path, minimum: int) -> list[str]:
    if label == "objdump":
        return ["objdump", "-x", str(target)]
    if label == "readelf":
        return ["readelf", "-a", str(target)]
    if label == "strings":
        return ["strings", "-a", "-n", str(minimum), str(target)]
    if label == "rabin2":
        return ["rabin2", "-Ij", str(target)]
    if label == "dumpbin":
        return ["dumpbin", "/headers", "/imports", str(target)]
    if label == "otool":
        return ["otool", "-hvL", str(target)]
    raise ValueError(f"unknown binary tool: {label}")


def auto_binary_tool(fmt: str) -> str | None:
    if fmt == "Java class":
        return None
    order = {
        "PE": ("dumpbin", "objdump", "rabin2"),
        "ELF": ("readelf", "objdump", "rabin2"),
        "Mach-O": ("otool", "objdump", "rabin2"),
    }.get(fmt, ("objdump", "rabin2", "dumpbin", "otool"))
    for name in order:
        if shutil.which(name):
            return name
    return None


def remaining_time(deadline: float, operation: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{operation} exceeded wall-clock timeout")
    return remaining


def set_response_timeout(response: Any, timeout: float) -> bool:
    raw = getattr(getattr(response, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is None:
        return False
    sock.settimeout(timeout)
    return True


class DeadlineRedirectHandler(HTTPRedirectHandler):
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Request | None:
        if urlsplit(newurl).scheme not in {"http", "https"}:
            raise HTTPError(newurl, code, "redirect outside HTTP(S) is not allowed", headers, fp)
        remaining = remaining_time(self.deadline, "HTTP probe")
        req.timeout = remaining
        set_response_timeout(fp, remaining)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def probe_http(url: str, method: str, timeout: float, body_limit: int) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("--http requires an http:// or https:// URL")
    started = time.monotonic()
    deadline = started + timeout
    request = Request(url, method=method, headers={"User-Agent": f"secure-software-evidence/{ADAPTER_VERSION}"})
    opener = build_opener(DeadlineRedirectHandler(deadline))
    try:
        response: Any = opener.open(request, timeout=remaining_time(deadline, "HTTP probe"))
    except HTTPError as error:
        response = error
    with response:
        remaining_time(deadline, "HTTP probe")
        body = bytearray()
        if method == "GET":
            read = getattr(response, "read1", response.read)
            while len(body) <= body_limit:
                remaining = remaining_time(deadline, "HTTP probe")
                if not set_response_timeout(response, remaining):
                    raise OSError("unable to enforce HTTP body deadline")
                chunk = read(min(64 * 1024, body_limit + 1 - len(body)))
                remaining_time(deadline, "HTTP probe")
                if not chunk:
                    break
                body.extend(chunk)
        captured = body[:body_limit]
        headers = {
            key.lower(): bounded(redact_url(value) if key.lower() == "location" else value, 1000)
            for key, value in response.headers.items()
            if key.lower() in SAFE_HTTP_HEADERS
        }
        truncated = len(body) > body_limit
        return {"type": "http", "method": method, "requested_url": redact_url(url),
                "final_url": redact_url(response.geturl()), "status": response.status,
                "duration_ms": round((time.monotonic() - started) * 1000), "headers": headers,
                "body": {"captured_bytes": len(captured), "truncated": truncated,
                         "sha256": hashlib.sha256(captured).hexdigest(),
                         "digest_scope": "captured-prefix" if truncated else "full-body"}}


def cert_name(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in value if isinstance(value, tuple) else ():
        for key, item in group if isinstance(group, tuple) else ():
            result[str(key)] = bounded(item, 500) or ""
    return result


def probe_tls(target: str, timeout: float) -> dict[str, Any]:
    parsed = urlsplit("//" + target)
    host, port = parsed.hostname, parsed.port or 443
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("--tls requires HOST or HOST:PORT")
    started = time.monotonic()
    deadline = started + timeout
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=remaining_time(deadline, "TLS probe")) as raw:
        raw.settimeout(remaining_time(deadline, "TLS probe"))
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.settimeout(remaining_time(deadline, "TLS probe"))
            cert = connection.getpeercert()
            der = connection.getpeercert(binary_form=True)
            return {"type": "tls", "target": f"{host}:{port}", "duration_ms": round((time.monotonic() - started) * 1000),
                    "version": connection.version(), "cipher": connection.cipher()[0] if connection.cipher() else None,
                    "peer": bounded(connection.getpeername()[0], 200), "certificate_sha256": hashlib.sha256(der).hexdigest(),
                    "subject": cert_name(cert.get("subject")), "issuer": cert_name(cert.get("issuer")),
                    "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                    "subject_alt_names": [bounded(item[1], 500) for item in cert.get("subjectAltName", ())[:100]]}


def read_json_artifact(path: Path) -> tuple[bytes, Any]:
    with path.open("rb") as handle:
        raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {path}")
    return raw, json.loads(raw)


def add_run(receipt: dict[str, Any], label: str, argv: list[str], cwd: Path, env: dict[str, str], args: argparse.Namespace,
            secrets: list[str]) -> dict[str, Any] | None:
    try:
        run = execute(label, argv, cwd, env, args.timeout, args.max_output_bytes, secrets)
        receipt["runs"].append(run)
        if run["timed_out"]:
            receipt["errors"].append({"stage": "execute", "tool": label, "message": "command timed out"})
        return run
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt["errors"].append({"stage": "execute", "tool": label, "message": redact_text(str(error), secrets)})
        return None


def collect_scan(receipt: dict[str, Any], args: argparse.Namespace, env: dict[str, str], secrets: list[str]) -> None:
    scope = Path(args.scope).resolve()
    if not scope.exists():
        raise ValueError(f"scope does not exist: {scope}")
    receipt["scope"] = str(scope)
    for sarif in args.sarif:
        path = Path(sarif).resolve()
        raw, data = read_json_artifact(path)
        if not isinstance(data, dict) or data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
            raise ValueError(f"expected SARIF 2.1.0 with a runs array: {path}")
        observations, tools = sarif_observations(data, args.max_observations - len(receipt["observations"]))
        receipt["artifacts"].append({**artifact(path, "sarif"), "tool_drivers": tools, "raw_sha256": hashlib.sha256(raw).hexdigest()})
        receipt["observations"].extend(observations)
    labels: list[str] = []
    for label in args.tool or ["auto"]:
        labels.extend(auto_scanners(scope) if label == "auto" else [label])
    labels = list(dict.fromkeys(labels))
    if not labels and not args.sarif and not args.command:
        receipt["errors"].append({"stage": "select", "message": "no matching installed scanner; select --tool, --sarif, or custom argv"})
    for label in labels:
        argv, cwd = scanner_command(label, scope)
        run = add_run(receipt, label, argv, cwd, env, args, secrets)
        if run and not run["stdout"]["truncated"]:
            receipt["observations"].extend(scanner_observations(label, run["stdout"]["preview"],
                                                                 args.max_observations - len(receipt["observations"])))
    if args.command:
        label = Path(args.command[0]).stem
        run = add_run(receipt, label, args.command, scope if scope.is_dir() else scope.parent, env, args, secrets)
        if run and not run["stdout"]["truncated"]:
            receipt["observations"].extend(scanner_observations(label, run["stdout"]["preview"],
                                                                 args.max_observations - len(receipt["observations"])))


def collect_binary(receipt: dict[str, Any], args: argparse.Namespace, env: dict[str, str], secrets: list[str]) -> None:
    target = Path(args.target).resolve()
    if not target.is_file():
        raise ValueError(f"binary target is not a file: {target}")
    receipt["scope"] = str(target)
    receipt["artifacts"].append(artifact(target, "binary"))
    metadata, strings = binary_metadata(target, args.strings_bytes, args.strings_min, args.strings_limit)
    receipt["observations"].extend((metadata, strings))
    labels = args.tool or ["auto"]
    for label in labels:
        selected = auto_binary_tool(metadata["format"]) if label == "auto" else label
        if selected:
            add_run(receipt, selected, binary_command(selected, target, args.strings_min), target.parent, env, args, secrets)
    if args.command:
        add_run(receipt, Path(args.command[0]).stem, args.command, target.parent, env, args, secrets)


def collect_runtime(receipt: dict[str, Any], args: argparse.Namespace, env: dict[str, str], secrets: list[str]) -> None:
    receipt["scope"] = "runtime"
    for url in args.http:
        try:
            receipt["observations"].append(probe_http(url, args.http_method, args.timeout, args.http_body_bytes))
        except (OSError, ValueError) as error:
            receipt["errors"].append({"stage": "http", "target": redact_url(url), "message": redact_text(str(error), secrets)})
    for target in args.tls:
        try:
            receipt["observations"].append(probe_tls(target, args.timeout))
        except (OSError, ValueError, ssl.SSLError) as error:
            receipt["errors"].append({"stage": "tls", "target": redact_url("tls://" + target).removeprefix("tls://"),
                                      "message": redact_text(str(error), secrets)})
    cwd = Path(args.cwd).resolve()
    if args.docker:
        run = add_run(receipt, "docker", ["docker", "version", "--format", "{{json .}}"], cwd, env, args, secrets)
        if run and not run["stdout"]["truncated"]:
            try:
                data = json.loads(run["stdout"]["preview"])
                if isinstance(data, dict):
                    receipt["observations"].append({"type": "docker", "client": data.get("Client"), "server": data.get("Server")})
            except json.JSONDecodeError:
                pass
    if args.kubectl:
        run = add_run(receipt, "kubectl", ["kubectl", "version", "--output=json"], cwd, env, args, secrets)
        if run and not run["stdout"]["truncated"]:
            try:
                data = json.loads(run["stdout"]["preview"])
                if isinstance(data, dict):
                    receipt["observations"].append({"type": "kubernetes", "client_version": data.get("clientVersion"),
                                                    "server_version": data.get("serverVersion")})
            except json.JSONDecodeError:
                pass
        add_run(receipt, "kubectl", ["kubectl", "auth", "can-i", "--list", "--all-namespaces"], cwd, env, args, secrets)
    if args.command:
        add_run(receipt, Path(args.command[0]).stem, args.command, cwd, env, args, secrets)
    if not any((args.http, args.tls, args.docker, args.kubectl, args.command)):
        receipt["errors"].append({"stage": "select", "message": "select --http, --tls, --docker, --kubectl, or custom argv"})


def write_receipt(path: Path, receipt: dict[str, Any], force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(f"output exists; pass --force to replace: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            os.unlink(temporary)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def apply_disclosure_policy(receipt: dict[str, Any], include_previews: bool,
                            include_string_values: bool) -> None:
    if not include_previews:
        for run in receipt.get("runs", []):
            if not isinstance(run, dict):
                continue
            for name in ("stdout", "stderr"):
                stream = run.get(name)
                if isinstance(stream, dict):
                    stream["preview"] = OMITTED_PREVIEW if stream.get("bytes") else ""
    if not include_string_values:
        for observation in receipt.get("observations", []):
            if not isinstance(observation, dict) or observation.get("type") != "bounded_strings":
                continue
            observation["values"] = [
                {
                    "offset": item.get("offset"),
                    "encoding": item.get("encoding"),
                    "characters": len(item.get("value", "")),
                    "value": OMITTED_PREVIEW,
                }
                for item in observation.get("values", [])
                if isinstance(item, dict)
            ]


def self_test() -> None:
    if not __debug__:
        raise RuntimeError("self-test requires assertions; run Python without -O")
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            if self.path.startswith("/redirect/"):
                index = int(urlsplit(self.path).path.rsplit("/", 1)[-1])
                time.sleep(0.08)
                self.send_response(302 if index < 2 else 200)
                if index < 2:
                    self.send_header("Location", f"/redirect/{index + 1}?code=fixture-secret-123")
                self.end_headers()
                if index == 2:
                    self.wfile.write(b"done")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Location", "https://example.test/next?token=fixture-secret-123")
            self.end_headers()
            if self.path == "/slow":
                try:
                    for _ in range(10):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass
            else:
                self.wfile.write(b"fixture-body")

        def log_message(self, _format: str, *args: Any) -> None:
            pass

    server_errors: list[BaseException] = []

    class TestServer(ThreadingHTTPServer):
        def handle_error(self, request: Any, client_address: Any) -> None:
            error = sys.exc_info()[1]
            if error is not None:
                server_errors.append(error)

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = dict(os.environ, ADAPTER_TEST_SECRET="fixture-secret-123")
        secrets = secret_values({"ADAPTER_TEST_SECRET": "fixture-secret-123"})
        run = execute("python", [sys.executable, "-c", "import os,json;print(json.dumps({'results':[{'id':'X','message':os.environ['ADAPTER_TEST_SECRET']}]}))"],
                      root, env, 5, 4096, secrets)
        assert run["exit_code"] == 0 and not run["timed_out"]
        assert "fixture-secret-123" not in run["stdout"]["preview"] and "<redacted>" in run["stdout"]["preview"]
        assert len(run["stdout"]["sha256"]) == 64
        bare_secret = "ghp_" + "A" * 36
        bare_run = execute("python", [sys.executable, "-c", f"print({bare_secret!r})"], root, env, 5, 4096, secrets)
        assert bare_secret not in bare_run["stdout"]["preview"]
        short_capture = Capture(64)
        short_capture.data.extend(b"a" * 64)
        short_capture.total = 64
        short_capture.digest.update(short_capture.data)
        short_preview = short_capture.receipt(["a"])["preview"]
        assert short_preview == OMITTED_PREVIEW and redact_value(short_preview, ["a"]) == OMITTED_PREVIEW
        truncated_capture = Capture(4)
        truncated_capture.data.extend(b"fixt")
        truncated_capture.total = len(b"fixture-secret-123")
        truncated_capture.digest.update(b"fixture-secret-123")
        assert "fixt" not in truncated_capture.receipt(["fixture-secret-123"])["preview"]
        truncated = execute("python", [sys.executable, "-c", "print('x'*10000)"], root, env, 5, 64, secrets)
        assert truncated["stdout"]["truncated"] and truncated["stdout"]["captured_bytes"] == 64
        timeout = execute("python", [sys.executable, "-c", "import time;time.sleep(3)"], root, env, 0.05, 1024, secrets)
        assert timeout["timed_out"]
        descendant_marker = root / "descendant-survived"
        descendant = f"import time;from pathlib import Path;time.sleep(.4);Path({str(descendant_marker)!r}).write_text('x')"
        inherited = f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{descendant!r}])"
        inherited_started = time.monotonic()
        inherited_run = execute("python", [sys.executable, "-c", inherited], root, env, 0.2, 1024, secrets)
        assert inherited_run["exit_code"] == 0 and time.monotonic() - inherited_started < 1.0
        time.sleep(0.5)
        assert not descendant_marker.exists()
        if os.name == "nt":
            containment_marker = root / "uncontained-started"
            original_job_factory = globals()["create_kill_job"]
            globals()["create_kill_job"] = lambda _proc: None
            try:
                try:
                    run_raw([sys.executable, "-c", f"from pathlib import Path;Path({str(containment_marker)!r}).write_text('x')"],
                            root, env, 1, 1024, secrets)
                    raise AssertionError("process ran without Windows tree containment")
                except OSError:
                    pass
            finally:
                globals()["create_kill_job"] = original_job_factory
            assert not containment_marker.exists()
        binary = root / "fixture.bin"
        binary.write_bytes(b"MZ" + b"\0" * 126 + b"fixture-visible-string\0")
        metadata, strings = binary_metadata(binary, 1024, 4, 10)
        assert metadata["format"] in {"unknown", "PE"}
        assert any(item["value"] == "fixture-visible-string" for item in strings["values"])
        binary.write_bytes(bytes.fromhex("CAFEBABE00000034") + b"\0" * 64)
        java, _ = binary_metadata(binary, 64, 4, 10)
        assert java["format"] == "Java class" and java["class_version"] == 52
        for magic, count in (("BEBAFECA", "02000000"), ("CAFEBABF", "00000002"), ("BFBAFECA", "02000000")):
            binary.write_bytes(bytes.fromhex(magic + count) + b"\0" * 64)
            universal, _ = binary_metadata(binary, 64, 4, 10)
            assert universal["format"] == "Mach-O" and universal["architectures"] == 2
        binary.write_bytes(bare_secret.encode())
        _, secret_strings = binary_metadata(binary, 1024, 4, 10)
        assert bare_secret not in json.dumps(redact_value(secret_strings, []))
        binary.write_bytes(b"\0".join(f"string-{index}".encode() for index in range(1000)))
        _, bounded_strings = binary_metadata(binary, binary.stat().st_size, 4, 10)
        assert bounded_strings["truncated"] and len(bounded_strings["values"]) == 10
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture", "version": "1"}},
                  "results": [{"ruleId": "R1", "level": "warning", "message": {"text": "lead"}}]}]}
        observations, tools = sarif_observations(sarif, 10)
        assert observations[0]["id"] == "R1" and tools[0]["name"] == "fixture"
        cargo = {"vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-1", "title": "lead"},
                 "package": {"name": "crate", "version": "1.0"}}]}}
        npm = {"vulnerabilities": {"pkg": {"severity": "high", "range": "<2", "via": [{"source": 1, "title": "lead"}]}}}
        assert scanner_observations("cargo-audit", json.dumps(cargo), 10)[0]["id"] == "RUSTSEC-1"
        assert scanner_observations("npm-audit", json.dumps(npm), 10)[0]["package"] == "pkg <2"
        assert scanner_observations("pip-audit", json.dumps({"dependencies": [{"name": "safe", "version": "1", "vulns": []}]}), 10) == []
        pip_vuln = scanner_observations("pip-audit", json.dumps(
            {"dependencies": [{"name": "pkg", "version": "1", "vulns": [{"id": "PYSEC-1"}]}]}
        ), 10)
        assert pip_vuln[0]["id"] == "PYSEC-1"
        python_project = root / "python-project"
        python_project.mkdir()
        (python_project / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='1'\n", encoding="utf-8")
        assert scanner_command("pip-audit", python_project)[0][-1] == str(python_project)
        (python_project / "pylock.toml").write_text("lock-version = '1.0'\n", encoding="utf-8")
        assert "--locked" in scanner_command("pip-audit", python_project)[0]
        go_stream = '{"config":{"protocol_version":"v1"}}\n{"finding":{"osv":"GO-1","trace":[{"package":"p"}]}}'
        assert scanner_observations("govulncheck", go_stream, 10)[0]["id"] == "GO-1"
        trivy = {"Results": [{"Target": "app", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p"}]}]}
        assert scanner_observations("trivy", json.dumps(trivy), 10)[0]["id"] == "CVE-1"
        detect = {"results": {"app.py": [{"type": "API Key", "line_number": 7}]}}
        assert scanner_observations("detect-secrets", json.dumps(detect), 10)[0]["location"] == "app.py:7"
        original_which = shutil.which
        shutil.which = lambda name, *args, **kwargs: name if name in {"dumpbin", "objdump", "rabin2", "readelf", "otool"} else None
        try:
            assert auto_binary_tool("PE") == "dumpbin"
            assert auto_binary_tool("ELF") == "readelf"
            assert auto_binary_tool("Mach-O") == "otool"
        finally:
            shutil.which = original_which
        server = TestServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            http = probe_http(f"http://127.0.0.1:{server.server_port}/", "GET", 2, 7)
            assert http["status"] == 200 and http["body"]["truncated"] and http["body"]["captured_bytes"] == 7
            assert http["body"]["digest_scope"] == "captured-prefix" and "fixture-secret-123" not in http["headers"]["location"]
            full_http = probe_http(f"http://127.0.0.1:{server.server_port}/", "GET", 2, 100)
            assert full_http["body"]["digest_scope"] == "full-body" and not full_http["body"]["truncated"]
            slow_started = time.monotonic()
            try:
                probe_http(f"http://127.0.0.1:{server.server_port}/slow", "GET", 0.15, 100)
                raise AssertionError("slow HTTP probe exceeded its deadline")
            except TimeoutError:
                assert time.monotonic() - slow_started < 0.6
            redirect_started = time.monotonic()
            try:
                probe_http(f"http://127.0.0.1:{server.server_port}/redirect/0", "GET", 0.12, 100)
                raise AssertionError("redirect chain exceeded its shared deadline")
            except TimeoutError:
                assert time.monotonic() - redirect_started < 0.2
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        assert not server_errors, server_errors
        disclosure = {
            "runs": [{"stdout": {"bytes": 6, "preview": "opaque"}, "stderr": {"bytes": 0, "preview": ""}}],
            "observations": [{"type": "bounded_strings", "values": [{"offset": 1, "encoding": "ascii", "value": "opaque"}]}],
        }
        apply_disclosure_policy(disclosure, False, False)
        assert disclosure["runs"][0]["stdout"]["preview"] == OMITTED_PREVIEW
        assert disclosure["observations"][0]["values"][0] == {
            "offset": 1, "encoding": "ascii", "characters": 6, "value": OMITTED_PREVIEW,
        }
        assert redact_argv(["tool", "--token", "secret", "https://user:pass@example.test/?api_key=x"])[2] == "<redacted>"
        assert "alice:password" not in redact_argv(["curl", "-u", "alice:password"])
        redacted_argv = redact_argv(["tool", "--github-token", "value", "--header=Authorization: Bearer value", "-HCookie: value"])
        assert "value" not in json.dumps(redacted_argv)
        assert "alpha beta gamma" not in redact_text('password="alpha beta gamma"', [])
        assert bare_secret not in redact_text(bare_secret, [])
        assert "abc" not in redact_url("https://example.test/file?X-Amz-Signature=abc")
        assert "fixture-secret" not in redact_url("/next?token=fixture-secret")
        assert "fixture-secret" not in redact_url("https://example.test/callback?code=fixture-secret")
        assert "fixture-secret" not in redact_url("https://example.test/hook/fixture-secret")
        try:
            probe_tls("user:password@127.0.0.1:1", 0.1)
            raise AssertionError("TLS userinfo was accepted")
        except ValueError:
            pass
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def hold_tls() -> None:
            connection, _address = listener.accept()
            with connection:
                time.sleep(0.4)

        tls_thread = threading.Thread(target=hold_tls, daemon=True)
        tls_thread.start()
        original_create_connection = socket.create_connection

        def delayed_connection(*call_args: Any, **call_kwargs: Any) -> socket.socket:
            time.sleep(0.06)
            return original_create_connection(*call_args, **call_kwargs)

        socket.create_connection = delayed_connection
        tls_started = time.monotonic()
        try:
            try:
                probe_tls(f"127.0.0.1:{listener.getsockname()[1]}", 0.12)
                raise AssertionError("TLS handshake exceeded its shared deadline")
            except (OSError, ssl.SSLError):
                assert time.monotonic() - tls_started < 0.2
        finally:
            socket.create_connection = original_create_connection
            listener.close()
            tls_thread.join(timeout=1)
        output = root / "receipt.json"
        write_receipt(output, {"schema_version": 1}, False)
        assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == 1
        try:
            write_receipt(output, {}, False)
            raise AssertionError("existing output was overwritten")
        except FileExistsError:
            pass
        race_output = root / "race.json"
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def race_writer(value: int) -> None:
            barrier.wait()
            try:
                write_receipt(race_output, {"writer": value}, False)
                outcomes.append("written")
            except FileExistsError:
                outcomes.append("exists")

        racers = [threading.Thread(target=race_writer, args=(index,)) for index in range(2)]
        for racer in racers:
            racer.start()
        for racer in racers:
            racer.join()
        assert sorted(outcomes) == ["exists", "written"]


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, required=True, help="Atomic JSON receipt path")
    parser.add_argument("--force", action="store_true", help="Replace an existing receipt")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per operation timeout in seconds")
    parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_CAPTURE_BYTES, help="Captured bytes per stdout/stderr stream")
    parser.add_argument("--max-observations", type=int, default=MAX_OBSERVATIONS)
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE", help="Process environment override; values are never recorded")
    parser.add_argument("--include-previews", action="store_true",
                        help="Include bounded redacted stdout/stderr previews; receipts may contain target data")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline safety and normalization checks")
    subparsers = parser.add_subparsers(dest="kind")
    scan = subparsers.add_parser("scan", help="Run installed scanners or ingest SARIF")
    add_common(scan)
    scan.add_argument("--scope", default=".")
    scan.add_argument("--tool", action="append", choices=("auto", "cargo-audit", "npm-audit", "semgrep", "bandit", "pip-audit",
                                                                    "trivy", "osv-scanner", "checkov", "tfsec", "gosec",
                                                                    "govulncheck", "detect-secrets"))
    scan.add_argument("--sarif", action="append", default=[], metavar="FILE")
    scan.add_argument("command", nargs=argparse.REMAINDER, help="Custom argv after --; started with shell=False")
    binary = subparsers.add_parser("binary", help="Hash and inspect one binary")
    add_common(binary)
    binary.add_argument("--target", required=True)
    binary.add_argument("--tool", action="append", choices=("auto", "objdump", "readelf", "strings", "rabin2", "dumpbin", "otool"))
    binary.add_argument("--strings-bytes", type=int, default=8 * 1024 * 1024)
    binary.add_argument("--strings-min", type=int, default=4)
    binary.add_argument("--strings-limit", type=int, default=200)
    binary.add_argument("--include-string-values", action="store_true",
                        help="Include bounded redacted string values; receipts may contain target data")
    binary.add_argument("command", nargs=argparse.REMAINDER, help="Custom argv after --; started with shell=False")
    runtime = subparsers.add_parser("runtime", help="Collect HTTP, TLS, Docker, Kubernetes, or custom runtime evidence")
    add_common(runtime)
    runtime.add_argument("--cwd", default=".")
    runtime.add_argument("--http", action="append", default=[], metavar="URL")
    runtime.add_argument("--http-method", choices=("HEAD", "GET"), default="HEAD")
    runtime.add_argument("--http-body-bytes", type=int, default=1024 * 1024)
    runtime.add_argument("--tls", action="append", default=[], metavar="HOST[:PORT]")
    runtime.add_argument("--docker", action="store_true")
    runtime.add_argument("--kubectl", action="store_true")
    runtime.add_argument("command", nargs=argparse.REMAINDER, help="Custom argv after --; started with shell=False")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("self-test: ok")
        return 0
    if not args.kind:
        raise SystemExit("select scan, binary, runtime, or --self-test")
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise SystemExit("--timeout must be finite and greater than zero")
    if not 1 <= args.max_output_bytes <= MAX_CAPTURE_BYTES:
        raise SystemExit(f"--max-output-bytes must be 1..{MAX_CAPTURE_BYTES}")
    if not 1 <= args.max_observations <= 10_000:
        raise SystemExit("--max-observations must be 1..10000")
    if args.kind == "binary" and not (1 <= args.strings_min <= 128 and 1 <= args.strings_limit <= 10_000
                                       and 1 <= args.strings_bytes <= MAX_ARTIFACT_BYTES):
        raise SystemExit("invalid bounded-string limits")
    if args.kind == "runtime" and not 0 <= args.http_body_bytes <= MAX_ARTIFACT_BYTES:
        raise SystemExit(f"--http-body-bytes must be 0..{MAX_ARTIFACT_BYTES}")
    overrides = parse_env(args.env)
    env = dict(os.environ, **overrides)
    secrets = secret_values(overrides)
    started = time.monotonic()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "adapter": {"name": "secure-software-evidence", "version": ADAPTER_VERSION},
        "kind": args.kind,
        "scope": None,
        "started_at": utc_now(),
        "finished_at": None,
        "duration_ms": None,
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "artifacts": [],
        "runs": [],
        "observations": [],
        "errors": [],
    }
    try:
        {"scan": collect_scan, "binary": collect_binary, "runtime": collect_runtime}[args.kind](receipt, args, env, secrets)
    except Exception as error:
        receipt["errors"].append({"stage": "collect", "message": redact_text(str(error), secrets)})
    receipt["observations"] = receipt["observations"][:args.max_observations]
    receipt["finished_at"] = utc_now()
    receipt["duration_ms"] = round((time.monotonic() - started) * 1000)
    apply_disclosure_policy(receipt, args.include_previews,
                            args.kind == "binary" and args.include_string_values)
    receipt = redact_value(receipt, secrets)
    write_receipt(args.output.resolve(), receipt, args.force)
    print(f"evidence receipt: {args.output.resolve()}")
    return 1 if receipt["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

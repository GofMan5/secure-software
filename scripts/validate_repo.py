#!/usr/bin/env python3
"""Validate the public Secure Software plugin without third-party dependencies."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "secure-software"
SKILL = PLUGIN / "skills" / "secure-software"
MANIFEST = PLUGIN / ".codex-plugin" / "plugin.json"
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
TEST_CASES = ROOT / "submission" / "test-cases.json"
SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
EXPECTED_SKILL_FILES = {
    "SKILL.md",
    "agents/openai.yaml",
    "references/attack-surface.md",
    "references/intelligence-sources.md",
    "references/platform-hardening.md",
    "scripts/fetch_threat_intel.py",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_manifest() -> None:
    manifest = load_json(MANIFEST)
    require(isinstance(manifest, dict), "plugin manifest must be an object")
    require(manifest.get("name") == PLUGIN.name, "plugin name must match its folder")
    require(isinstance(manifest.get("version"), str) and SEMVER.fullmatch(manifest["version"]), "invalid semver")
    require(manifest.get("skills") == "./skills/", "skills path must be ./skills/")
    require(manifest.get("license") == "MIT OR Apache-2.0", "unexpected license expression")
    require(isinstance(manifest.get("author"), dict) and manifest["author"].get("name"), "author.name is required")

    interface = manifest.get("interface")
    require(isinstance(interface, dict), "interface metadata is required")
    require(0 < len(interface.get("displayName", "")) <= 30, "displayName must be 1-30 characters")
    require(0 < len(interface.get("shortDescription", "")) <= 30, "shortDescription must be 1-30 characters")
    require(0 < len(interface.get("longDescription", "")) <= 4_000, "longDescription must be 1-4000 characters")
    require(interface.get("category") == "Security", "plugin category must be Security")
    capabilities = interface.get("capabilities")
    require(isinstance(capabilities, list) and 1 <= len(capabilities) <= 20, "capabilities must contain 1-20 entries")
    prompts = interface.get("defaultPrompt")
    require(isinstance(prompts, list) and 1 <= len(prompts) <= 3, "defaultPrompt must contain 1-3 entries")
    require(all(isinstance(item, str) and 0 < len(item) <= 128 and "\n" not in item for item in prompts), "invalid starter prompt")
    for field in ("composerIcon", "logo"):
        value = interface.get(field)
        require(isinstance(value, str) and value.startswith("./"), f"{field} must be plugin-relative")
        target = (PLUGIN / value).resolve()
        require(target.is_relative_to(PLUGIN.resolve()) and target.is_file(), f"missing {field}: {value}")


def validate_marketplace() -> None:
    marketplace = load_json(MARKETPLACE)
    require(isinstance(marketplace, dict) and marketplace.get("name") == "secure-software", "unexpected marketplace name")
    entries = marketplace.get("plugins")
    require(isinstance(entries, list) and len(entries) == 1, "marketplace must contain exactly one plugin")
    entry = entries[0]
    require(entry.get("name") == "secure-software", "marketplace plugin name mismatch")
    require(entry.get("source") == {"source": "local", "path": "./plugins/secure-software"}, "invalid marketplace source")
    require(entry.get("category") == "Security", "marketplace category must be Security")
    require(entry.get("policy") == {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}, "invalid marketplace policy")


def validate_skill() -> None:
    actual = {
        path.relative_to(SKILL).as_posix()
        for path in SKILL.rglob("*")
        if path.is_file()
    }
    require(actual == EXPECTED_SKILL_FILES, f"unexpected skill tree: {sorted(actual ^ EXPECTED_SKILL_FILES)}")
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    require(text.startswith("---\n") and "\n---\n" in text[4:], "SKILL.md frontmatter is malformed")
    frontmatter = text.split("---", 2)[1]
    require(re.search(r"(?m)^name:\s*secure-software\s*$", frontmatter) is not None, "skill name mismatch")
    require(re.search(r"(?m)^description:\s*.+$", frontmatter) is not None, "skill description is missing")


def validate_markdown_links() -> None:
    for path in ROOT.rglob("*.md"):
        for raw in MARKDOWN_LINK.findall(path.read_text(encoding="utf-8")):
            target = raw.strip().split("#", 1)[0]
            if not target or "://" in target or target.startswith(("mailto:", "codex:")):
                continue
            require((path.parent / target).resolve().exists(), f"broken relative link in {path.relative_to(ROOT)}: {raw}")


def validate_text_and_artifacts() -> None:
    for path in ROOT.rglob("*"):
        if path.name == "__pycache__" or path.suffix == ".pyc":
            raise ValueError(f"generated Python artifact present: {path.relative_to(ROOT)}")
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".json", ".yaml", ".yml", ".svg", ".cff"}:
            continue
        require(BIDI.search(path.read_text(encoding="utf-8")) is None, f"bidirectional control in {path.relative_to(ROOT)}")


def validate_submission_cases() -> None:
    data = load_json(TEST_CASES)
    require(isinstance(data, dict) and data.get("schema_version") == 1, "invalid test-case schema")
    positive = data.get("positive")
    negative = data.get("negative")
    require(isinstance(positive, list) and len(positive) == 5, "exactly five positive cases are required")
    require(isinstance(negative, list) and len(negative) == 3, "exactly three negative cases are required")
    cases = positive + negative
    require(len({case.get("id") for case in cases}) == 8, "test-case IDs must be unique")
    for case in cases:
        require(all(isinstance(case.get(key), str) and case[key].strip() for key in ("id", "prompt", "expected_behavior", "expected_result")), f"incomplete test case: {case}")


def run_self_test() -> None:
    script = SKILL / "scripts" / "fetch_threat_intel.py"
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    subprocess.run([sys.executable, "-B", str(script), "--self-test"], check=True, cwd=ROOT, env=env)


def main() -> int:
    validate_manifest()
    validate_marketplace()
    validate_skill()
    validate_markdown_links()
    validate_text_and_artifacts()
    validate_submission_cases()
    run_self_test()
    print("repository validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a deterministic public-directory ZIP with one plugin root."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
import validate_repo

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "secure-software"
DIST = ROOT / "dist"


def main() -> int:
    validate_repo.main()
    version = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]
    DIST.mkdir(exist_ok=True)
    output = DIST / f"secure-software-{version}.zip"
    files = sorted(
        (path for path in PLUGIN.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(PLUGIN).as_posix(),
    )
    checksum = DIST / "SHA256SUMS.txt"
    with tempfile.TemporaryDirectory(prefix=".package-", dir=DIST) as directory:
        staging = Path(directory)
        staged_output = staging / output.name
        staged_checksum = staging / checksum.name
        with zipfile.ZipFile(staged_output, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in files:
                relative = path.relative_to(PLUGIN)
                info = zipfile.ZipInfo((Path("secure-software") / relative).as_posix(), (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
        digest = hashlib.sha256(staged_output.read_bytes()).hexdigest()
        with zipfile.ZipFile(staged_output) as archive:
            names = archive.namelist()
            bad_entry = archive.testzip()
        require_root = {PurePosixPath(name).parts[0] for name in names}
        if (
            require_root != {"secure-software"}
            or names != sorted(names)
            or bad_entry is not None
            or staged_output.stat().st_size > 100 * 1024 * 1024
        ):
            raise ValueError("submission archive must be sorted, intact, contain one plugin root, and remain under 100 MiB")
        staged_checksum.write_text(f"{digest}  {output.name}\n", encoding="utf-8", newline="\n")
        backup = staging / "previous.zip"
        had_output = output.exists()
        if had_output:
            shutil.copy2(output, backup)
        os.replace(staged_output, output)
        try:
            os.replace(staged_checksum, checksum)
        except BaseException:
            if had_output:
                os.replace(backup, output)
            else:
                output.unlink(missing_ok=True)
            raise
    print(f"built {output}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

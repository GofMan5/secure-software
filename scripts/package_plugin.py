#!/usr/bin/env python3
"""Build a deterministic public-directory ZIP with one plugin root."""

from __future__ import annotations

import hashlib
import json
import sys
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
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(PLUGIN)
            info = zipfile.ZipInfo((Path("secure-software") / relative).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        bad_entry = archive.testzip()
    require_root = {PurePosixPath(name).parts[0] for name in names}
    if (
        require_root != {"secure-software"}
        or names != sorted(names)
        or bad_entry is not None
        or output.stat().st_size > 100 * 1024 * 1024
    ):
        raise ValueError("submission archive must be sorted, intact, contain one plugin root, and remain under 100 MiB")
    (DIST / "SHA256SUMS.txt").write_text(f"{digest}  {output.name}\n", encoding="utf-8", newline="\n")
    print(f"built {output}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

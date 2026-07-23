#!/usr/bin/env python3
"""Build a deterministic public-directory ZIP with one plugin root."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

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
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(item for item in PLUGIN.rglob("*") if item.is_file()):
            relative = path.relative_to(PLUGIN)
            info = zipfile.ZipInfo((Path("secure-software") / relative).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    require_root = {Path(name).parts[0] for name in zipfile.ZipFile(output).namelist()}
    if require_root != {"secure-software"} or output.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("submission archive must contain one plugin root and remain under 100 MiB")
    (DIST / "SHA256SUMS.txt").write_text(f"{digest}  {output.name}\n", encoding="utf-8", newline="\n")
    print(f"built {output}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

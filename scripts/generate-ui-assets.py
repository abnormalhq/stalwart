#!/usr/bin/env python3
"""Regenerate embedded UI assets without minifying their checked-in sources."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "resources" / "html-templates"
GZIP_ASSETS = {
    "ui.js": "ui.js.min.gz",
    "ui.css": "ui.css.min.gz",
    "login.html": "login.html.min.gz",
    "calendar-rsvp.html": "calendar-rsvp.html.min.gz",
}
SOURCE_COPIES = {
    "login.html": "login.html.min",
    "calendar-rsvp.html": "calendar-rsvp.html.min",
}


def deterministic_gzip(source: bytes) -> bytes:
    data = gzip.compress(source, compresslevel=9, mtime=0)
    return data[:9] + b"\xff" + data[10:]


def expected_outputs() -> dict[Path, bytes]:
    ui_hash = hashlib.sha256(
        (ASSETS / "ui.js").read_bytes() + b"\0" + (ASSETS / "ui.css").read_bytes()
    ).hexdigest()[:12]

    def source_bytes(name: str) -> bytes:
        content = (ASSETS / name).read_bytes()
        if name in {"login.html", "calendar-rsvp.html"}:
            content = content.replace(b"ui-HASH.css", f"ui-{ui_hash}.css".encode())
            content = content.replace(b"ui-HASH.js", f"ui-{ui_hash}.js".encode())
        return content

    outputs = {
        ASSETS / target: deterministic_gzip(source_bytes(source))
        for source, target in GZIP_ASSETS.items()
    }
    outputs.update(
        {
            ASSETS / target: source_bytes(source)
            for source, target in SOURCE_COPIES.items()
        }
    )
    outputs[ASSETS / "ui.hash"] = ui_hash.encode("ascii")
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generated assets do not match their sources",
    )
    args = parser.parse_args()

    outputs = expected_outputs()
    stale = [path for path, content in outputs.items() if not path.exists() or path.read_bytes() != content]
    if args.check:
        if stale:
            print("Generated assets need updating:")
            for path in stale:
                print(f"  {path.relative_to(ROOT)}")
            return 1
        print("Embedded UI assets match their sources.")
        return 0

    for path, content in outputs.items():
        path.write_bytes(content)
    print(f"Regenerated {len(outputs)} embedded UI assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
check_zerogate.py

Run this script after your rebrand to verify that no old identifiers
are left in the repository.

Usage:
    python3 check_zerogate.py
"""

import os
import re
from pathlib import Path

from loguru import logger

# ----------------------------------------------------------------------
# 1. Patterns to look for (case‑sensitive)
# ----------------------------------------------------------------------
OLD_TOKENS = [
    r"zerogate",
    r"ZeroGate",
    r"ZeroGate",
    r"zerogate",
    r"ZEROGATE",
]
PATTERN = re.compile("|".join(OLD_TOKENS))

# ----------------------------------------------------------------------
# 2. Exclusion rules
# ----------------------------------------------------------------------
IGNORE_DIRS = {".git", ".idea", "__pycache__", "node_modules"}
IGNORE_FILES = {"check_zerogate.py", "rebrand_zerogate.py", "rebrand_zerogate.sh"}
BINARY_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".ico",
    ".svg",
    ".eot",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".mp4",
    ".mp3",
    ".wav",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
}


def is_text_file(path: Path) -> bool:
    """Heuristic – try to decode a small chunk as UTF‑8."""
    if path.suffix.lower() in BINARY_EXTS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        chunk.decode("utf-8")
        return True
    except Exception:
        return False


def scan_for_tokens(root: Path):
    remaining = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Remove ignored directories from traversal
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for fname in filenames:
            if fname in IGNORE_FILES:
                continue
            fpath = Path(dirpath) / fname
            if not is_text_file(fpath):
                continue
            try:
                text = fpath.read_text(encoding="utf-8")
            except Exception:
                continue
            if PATTERN.search(text):
                remaining.append(fpath.relative_to(root))
    return remaining


def main():
    root = Path.cwd()
    leftovers = scan_for_tokens(root)

    if leftovers:
        logger.warning(f"Found {len(leftovers)} old tokens in:")
        for f in leftovers:
            logger.info(f"  - {f}")
    else:
        logger.success("No old tokens found! Rebrand looks solid.")


if __name__ == "__main__":
    main()

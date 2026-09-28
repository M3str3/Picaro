#!/usr/bin/env python3
"""Render the docs with Material for MkDocs in a container.

Runs the official ``squidfunk/mkdocs-material`` image against this repository,
so no local Python packages (or MkDocs install) are needed beyond the standard
library. One script replaces the per-OS shell wrappers and behaves the same on
Linux, macOS and Windows.

Usage:
    python scripts/docs.py                 # live server on http://localhost:8000
    python scripts/docs.py build           # static site into ./site
    python scripts/docs.py build --strict  # fail on warnings (broken links, ...)

Set ``PICARO_DOCS_IMAGE`` to use a different image tag.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# The repository root (this file lives in scripts/). It is mounted at /docs,
# which is where mkdocs.yml and `docs_dir` expect to be.
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("PICARO_DOCS_IMAGE", "squidfunk/mkdocs-material:9")
CONTAINER_DIR = "/docs"
PORT = 8000


def build_command(args: list[str]) -> list[str]:
    """Assemble the `docker run` argv.

    Docker wants forward slashes in the bind spec, which ``as_posix`` gives on
    every platform; the default action is a live server on 0.0.0.0 so the
    published port is reachable from the host.
    """
    print("http://localhost:8000")
    action = args or ["serve", f"--dev-addr=0.0.0.0:{PORT}"]

    command = ["docker", "run", "--rm"]
    if action[0] == "serve":
        command += ["-p", f"{PORT}:{PORT}"]
    # f"{ROOT.as_posix()}:{CONTAINER_DIR}" -> e.g. C:/code/picaro:/docs
    command += ["-v", f"{ROOT.as_posix()}:{CONTAINER_DIR}", IMAGE, *action]
    return command


def main(argv: list[str]) -> int:
    command = build_command(argv)
    if os.environ.get("PICARO_DOCS_PRINT"):
        print(" ".join(command))
        return 0
    try:
        return subprocess.call(command)
    except FileNotFoundError:
        sys.stderr.write("docs: 'docker' was not found on PATH.\n")
        return 127


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

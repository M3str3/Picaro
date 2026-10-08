#!/usr/bin/env python3
"""Render the docs with Astro (Starlight) in a container.

Builds a small Node image once (Astro + Starlight and their dependencies), then
runs it with the repository bind-mounted at ``/docs``. The content and the
navigation sidebar are generated *inside the container* by
``docs/site/scripts/assemble-docs.mjs`` from ``docs/`` + ``docs/nav.yml``, so no
local Node install is needed beyond Docker and the Python standard library.

Usage:
    python scripts/docs.py                 # live server on http://localhost:8000
    python scripts/docs.py build           # static site into ./site
    python scripts/docs.py build --rebuild # force a no-cache image build

Set ``PICARO_DOCS_IMAGE`` to use a different image tag.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# This file lives in scripts/, so its parent is the repository root.
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("PICARO_DOCS_IMAGE", "picaro-docs:latest")
DOCKERFILE = ROOT / "docs" / "site" / "Dockerfile"
CONTAINER_DIR = "/docs"
PORT = 8000

# The Starlight project is baked into the image at /app. Content and the
# sidebar are generated there from the /docs bind mount at run time.
APP_CONTENT = "/app/src/content/docs"
APP_SIDEBAR = "/app/src/sidebar.mjs"


def assemble_command() -> str:
    """The shell command that regenerates content + sidebar inside the container."""
    return (
        "node scripts/assemble-docs.mjs"
        f" --root {CONTAINER_DIR}"
        f" --out {APP_CONTENT}"
        f" --sidebar-out {APP_SIDEBAR}"
    )


def build_image(no_cache: bool) -> None:
    print(f"building docs image {IMAGE} …")
    command = ["docker", "build", "-f", str(DOCKERFILE), "-t", IMAGE]
    if no_cache:
        command.append("--no-cache")
    command.append(str(ROOT))
    subprocess.check_call(command)


def ensure_image(rebuild: bool) -> None:
    # Always build: the Docker layer cache makes this near-instant when nothing
    # under docs/site/ changed, and it guarantees the image always reflects the
    # current config/styles/assembler. `--rebuild` forces a full no-cache build.
    build_image(no_cache=rebuild)


def run(action: str, command: list[str]) -> int:
    # `--init` makes a signal-forwarding init PID 1, so a forwarded Ctrl+C
    # actually stops the container (a bare `sh -c` ignores it as PID 1).
    docker = ["docker", "run", "--rm", "--init"]
    # A TTY lets the terminal send SIGINT straight to the dev server; without
    # it docker only proxies signals in non-TTY mode.
    if action == "serve" and sys.stdin.isatty():
        docker += ["-it"]
    if action == "serve":
        docker += ["-p", f"{PORT}:{PORT}"]
    docker += ["-v", f"{ROOT.as_posix()}:{CONTAINER_DIR}"]
    if action == "build":
        site_dir = ROOT / "site"
        site_dir.mkdir(exist_ok=True)
        docker += ["-v", f"{site_dir.as_posix()}:/app/dist"]
    docker.append(IMAGE)
    docker += command

    proc = subprocess.Popen(docker)
    try:
        return proc.wait()
    except KeyboardInterrupt:
        # docker got the same Ctrl+C and is shutting the container down; wait
        # for it so `--rm` removes the container, instead of SIGKILLing the
        # client and orphaning a still-running container. A second Ctrl+C
        # gives up and forces the client down.
        print("stopping …", file=sys.stderr)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            proc.kill()
            return proc.wait()


def main(argv: list[str]) -> int:
    args = list(argv)
    rebuild = "--rebuild" in args
    args = [a for a in args if a != "--rebuild"]

    action = "build" if args and args[0] == "build" else "serve"
    # `build --strict` is accepted for backwards compatibility; Astro has no
    # strict link-check mode, so the flag is a harmless no-op.

    if os.environ.get("PICARO_DOCS_PRINT"):
        print(" ".join(args))
        return 0

    try:
        ensure_image(rebuild)
    except subprocess.CalledProcessError:
        return 1
    except FileNotFoundError:
        sys.stderr.write("docs: 'docker' was not found on PATH.\n")
        return 127

    if action == "serve":
        print(f"http://localhost:{PORT}")
        command = [
            "sh",
            "-c",
            f"{assemble_command()} && npm run dev -- --port {PORT} --host 0.0.0.0",
        ]
    else:
        command = ["sh", "-c", f"{assemble_command()} && npm run build"]

    return run(action, command)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

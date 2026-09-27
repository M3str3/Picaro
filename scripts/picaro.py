#!/usr/bin/env python3
"""Run the picaro packer inside its Docker image.

Builds the image on first use (or when ``--build`` comes first) and runs it
against the current directory with every argument passed through unchanged. One
script replaces the former per-OS shell wrappers and behaves the same on Linux,
macOS and Windows; it needs only the standard library.

Usage:
    python scripts/picaro.py build examples/plans/reflective-loading.yaml
    python scripts/picaro.py audit dist/test_packed_reflective.exe
    python scripts/picaro.py techniques list
    python scripts/picaro.py --build build plan.yaml   # force a rebuild

Environment:
    PICARO_IMAGE   image tag to build and run (default: picaro:latest)
    PICARO_PRINT   when set, print the `docker run` command instead of running it
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# This script lives in scripts/.
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("PICARO_IMAGE", "picaro:latest")

# An absolute Windows path: a drive letter ("C:/...") or a UNC path ("//...").
WINDOWS_ABSOLUTE = re.compile(r"(?i)^[a-z]:/|^//")


def translate_arg(arg: str, workdir: Path) -> str:
    """Rewrite a Windows path argument into the form the Linux container sees.

    The container is Linux, so backslashes are not path separators there. A
    relative path (`".\\examples\\x.yaml"`, `"dist\\y.exe"`) becomes a POSIX one,
    and an absolute path under the mounted directory becomes `"/work/..."`. Any
    other absolute path is left untouched: a value like
    `"C:\\Windows\\System32\\svchost.exe"` is an opaque `$arg.N$` the stub uses
    at runtime on Windows, not a path the container resolves.
    """
    if "\\" not in arg:
        return arg

    normalized = arg.replace("\\", "/")
    if not WINDOWS_ABSOLUTE.match(normalized):
        return normalized

    mount = workdir.as_posix().rstrip("/")
    if (
        len(normalized) > len(mount)
        and normalized[: len(mount)].lower() == mount.lower()
        and normalized[len(mount)] == "/"
    ):
        return "/work" + normalized[len(mount):]
    return arg


def build_command(args: list[str], workdir: Path, interactive: bool) -> list[str]:
    """Assemble the `docker run` argv.

    The current directory is mounted at /work: plans and payloads are read from
    it and outputs (dist/...) are written back through the same mount.
    """
    command = ["docker", "run", "--rm"]
    if interactive:
        command.append("-it")
    command += ["-v", f"{workdir.as_posix()}:/work", "-w", "/work", IMAGE, *args]
    return command


def image_exists() -> bool:
    return (
        subprocess.call(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        == 0
    )


def build_image() -> int:
    return subprocess.call(["docker", "build", "-t", IMAGE, str(ROOT)])


def main(argv: list[str]) -> int:
    args = list(argv)
    force_build = bool(args) and args[0] == "--build"
    if force_build:
        args = args[1:]

    workdir = Path.cwd()
    if os.name == "nt":
        args = [translate_arg(arg, workdir) for arg in args]

    # Allocate a TTY only when stdout is a real console, so color auto-detection
    # keeps working and piping still succeeds.
    interactive = sys.stdout.isatty()

    if os.environ.get("PICARO_PRINT"):
        print(" ".join(build_command(args, workdir, interactive)))
        return 0

    if force_build:
        code = build_image()
        if code != 0:
            return code
    elif not image_exists():
        sys.stderr.write(f"picaro: building image {IMAGE} (first run)...\n")
        code = build_image()
        if code != 0:
            return code

    try:
        return subprocess.call(build_command(args, workdir, interactive))
    except FileNotFoundError:
        sys.stderr.write("picaro: 'docker' was not found on PATH.\n")
        return 127
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Run the picaro packer inside its Docker image.

Builds the image on first use (or when the rebuild flag is passed) and runs it
against the current directory with every argument passed through unchanged. One
script replaces the former per-OS shell wrappers and behaves the same on Linux,
macOS and Windows; it needs only the standard library.

Usage:
    python scripts/picaro.py build examples/plans/reflective-loading.yaml
    python scripts/picaro.py audit dist/test_packed_reflective.exe
    python scripts/picaro.py techniques list
    python scripts/picaro.py --rebuild build plan.yaml   # rebuild the image first

The rebuild flag (`--rebuild`, or the older `--build`) may appear anywhere in
the arguments; everything else is passed to picaro unchanged.

Environment:
    PICARO_IMAGE   image tag to build and run (default: picaro:latest)
    PICARO_PRINT   when set, print the `docker run` command instead of running it
    PICARO_USER    `--user` value for the container (default: the invoking user
                   on Linux; set it to the empty string to run as the image user)
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

# Flags that force a `docker build` before the run. `--rebuild` is the explicit
# spelling; `--build` predates it and stays as an alias. Either may appear
# anywhere, since picaro itself has no such option.
REBUILD_FLAGS = frozenset({"--build", "--rebuild"})

# The container's scratch directory for intermediate artifacts. The image bakes
# its source in at /usr/src/picaro, and the packer writes `build/` next to it,
# which the invoking user cannot touch; point it at a writable path instead.
SCRATCH_DIR = "/tmp/picaro-build"


def is_tty(stream: object) -> bool:
    """Whether `stream` is a real terminal (and not `None`, e.g. closed stdio)."""
    return stream is not None and getattr(stream, "isatty", lambda: False)()


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


def rootless_docker() -> bool:
    """Whether the Docker daemon runs rootless (uid-mapped).

    A rootless daemon lives in a user namespace where the host user *is* the
    container's root, so a root container already writes files as the host user
    and forcing `--user <uid>` would run the process as an unmapped sub-uid that
    cannot write the mounted directory.
    """
    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.SecurityOptions}}"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return probe.returncode == 0 and "rootless" in probe.stdout


def container_user() -> str | None:
    """The `--user` value that stops the container writing root-owned files.

    On a Linux host a bind mount carries the container's uid straight to the
    host, and the image runs as root, so every output (`dist/...`, the `.picaro`
    lab certificate state) would be owned by root. Running the container as the
    invoking user avoids that. Docker Desktop (macOS, Windows) and rootless
    Docker already map ownership to the host user, so nothing is passed there;
    `PICARO_USER` overrides the choice, and an empty value disables it.
    """
    if "PICARO_USER" in os.environ:
        return os.environ["PICARO_USER"] or None
    if not sys.platform.startswith("linux") or not hasattr(os, "getuid"):
        return None
    if rootless_docker():
        return None
    return f"{os.getuid()}:{os.getgid()}"


def build_command(args: list[str], workdir: Path, interactive: bool) -> list[str]:
    """Assemble the `docker run` argv.

    The current directory is mounted at /work: plans and payloads are read from
    it and outputs (dist/...) are written back through the same mount. The
    container runs as the invoking user where that matters (see
    [`container_user`]) and keeps its scratch files out of the read-only source
    tree (`PICARO_BUILD_DIR`).
    """
    command = ["docker", "run", "--rm"]
    if interactive:
        command.append("-it")
    user = container_user()
    if user is not None:
        command += ["--user", user]
    command += [
        "-e",
        f"PICARO_BUILD_DIR={SCRATCH_DIR}",
        "-v",
        f"{workdir.as_posix()}:/work",
        "-w",
        "/work",
        IMAGE,
        *args,
    ]
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
    force_build = any(arg in REBUILD_FLAGS for arg in args)
    if force_build:
        args = [arg for arg in args if arg not in REBUILD_FLAGS]

    workdir = Path.cwd()
    if os.name == "nt":
        args = [translate_arg(arg, workdir) for arg in args]

    # Allocate a TTY only when both streams are real terminals, so color
    # auto-detection keeps working, piping still succeeds, and a terminal with
    # no readable stdin (some Windows consoles) does not trip docker's
    # "the input device is not a TTY".
    interactive = is_tty(sys.stdout) and is_tty(sys.stdin)

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

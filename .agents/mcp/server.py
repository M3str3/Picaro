#!/usr/bin/env python3
"""Picaro lab MCP server: analysis, gated execution, and an agent-driven debugger.

Run it in a console and point Zed (or any MCP client) at it over loopback:

    python .agents/mcp/server.py --lab --port 8787

The console is the live log of the session; the client speaks MCP over HTTP
(`http://127.0.0.1:8787/mcp`). Three tool families:

  * **inert prep**: `audit_file`, `hash_file`, `pe_info`, `build_plan`,
    `defender_status` -- reading or compiling a binary is not executing it.
  * **execution**: `run_artifact` -- runs a PE *without* the debugger, for
    control comparisons (e.g. anti-debug behavior with and without a debugger).
  * **debugging**: launch/attach, breakpoints, continue/step, registers,
    memory (read/write/scan), stack, threads, modules, disassembly, evaluate.

Everything that executes a target is a lab operation: those tools only exist
with `--lab` (or PICARO_MCP_LAB=1) and refuse to run while Windows Defender's
real-time protection is on. See README.md for the lldb requirements.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import deque
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SERVER_NAME = "picaro-debugger"
SERVER_VERSION = "0.6.0"
PROTOCOL_FALLBACK = "2025-06-18"

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import debugger  # noqa: E402 - same directory, after sys.path setup

LAB_ENABLED = os.environ.get("PICARO_MCP_LAB") == "1"

OUTPUT_LIMIT = 60_000  # characters returned per captured stream
JSON_LIMIT = 120_000  # characters of `picaro audit --json` returned verbatim

DEFAULT_RUN_TIMEOUT = 60
DEFAULT_BUILD_TIMEOUT = 600
DEFAULT_CONTINUE_TIMEOUT = 30
DEFAULT_STEP_TIMEOUT = 30

EVENT_LIMIT = 2000  # activity events kept in memory for `activity_log`
HEARTBEAT_INTERVAL = 30  # "still running" lines while a long child call blocks

DEBUG_LOCK = threading.RLock()
SESSION: "debugger.Session | None" = None

INSTRUCTIONS = (
    "picaro-debugger MCP server: an lldb-backed debugger plus static helpers. "
    "Inert tools (hash_file, pe_info, export_lookup, disassemble_file, "
    "strings_file, audit_file, yara_scan, techniques_list, technique_show, "
    "techniques_validate, build_plan, defender_status, activity_log) are safe "
    "anywhere. run_artifact and every debug_*/bp_*/step/"
    "run_until_event tool execute or drive a target and only exist with --lab on "
    "the isolated lab host (Defender real-time protection off). Every tool call, "
    "every debugger stop and every line the target prints goes to the server's "
    "activity log (console + a session log file); read it back with "
    "activity_log. Debug loop: build_plan with "
    "debug=true and name=<dir> for a stable build/<dir>/main.rs (omit name for a "
    "unique build/run-*/), debug_launch the stub_exe, bp_set on a crate-qualified "
    "Rust symbol (main::step_0::payload) or file:line, run_until_event, then registers / "
    "read_memory / stack. System-DLL APIs have no offline symbols: "
    "export_lookup then bp_set(@address). Static assembly of a file: "
    "disassemble_file."
)


class ToolError(Exception):
    """A failure the agent should read and act on (maps to isError)."""


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# activity log: the console, a session log file and an in-memory ring buffer
# ---------------------------------------------------------------------------

LOG_LOCK = threading.RLock()
EVENTS: "deque[dict]" = deque(maxlen=EVENT_LIMIT)
EVENT_SEQ = 0
LOG_PATH: Path | None = None

# The console is a diagnostic side-channel, not the transport: a stdout that
# blocks (a pipe nobody drains, a terminal paused with Ctrl+S) must never wedge a
# tool call. `print` there would (it runs before the handler returns, so a full
# 4 KiB pipe hangs the request until the client times out), so lines go through a
# single daemon pump instead. Ordering is preserved; only the console is async.
_CONSOLE_QUEUE: "queue.Queue[str]" = queue.Queue(maxsize=5000)


def _console_pump() -> None:
    while True:
        line = _CONSOLE_QUEUE.get()
        try:
            print(line, flush=True)
        except (UnicodeEncodeError, OSError):
            pass


threading.Thread(target=_console_pump, daemon=True, name="picaro-console").start()


def log(message: str, *, kind: str = "note", level: str = "info") -> None:
    """Record one activity line: console, session log file and ring buffer.

    The console (where the user started the server) is the live view; the file
    is the transcript to read afterwards, and the buffer is what the
    `activity_log` tool hands back to the agent. `kind` groups events: `tool`
    (a tool call or its result), `debug` (session events: launch, stops,
    breakpoints), `target` (a line the debuggee printed), `error`, `note`.
    """
    global EVENT_SEQ
    stamp = time.strftime("%H:%M:%S")
    line = f"[{stamp}] {message}"
    with LOG_LOCK:
        EVENT_SEQ += 1
        EVENTS.append(
            {
                "seq": EVENT_SEQ,
                "time": stamp,
                "kind": kind,
                "level": level,
                "text": message,
            }
        )
        if LOG_PATH is not None:
            # Reopened per line on purpose: low volume, and the transcript stays
            # readable (and tail-able) while the server runs.
            try:
                with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass
    # Enqueue, never block: a wedged console must neither stall the caller nor
    # grow without bound (the session log file keeps every line regardless).
    try:
        _CONSOLE_QUEUE.put_nowait(line)
    except queue.Full:
        pass


def format_arguments(arguments: dict, limit: int = 240) -> str:
    """Render tool arguments for one log line (`plan="x.yaml" debug=true`)."""
    parts = []
    for key, value in arguments.items():
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        text = str(text)
        if len(text) > 60:
            text = text[:57] + "..."
        parts.append(f"{key}={text}")
    return " ".join(parts)[:limit]


@contextmanager
def heartbeat(label: str, interval: float = HEARTBEAT_INTERVAL):
    """Log `<label>: still running (Ns)` while a long child call blocks.

    A debug stub takes tens of seconds to compile; without this the console
    looks dead for the whole build.
    """
    done = threading.Event()
    started = time.time()

    def beat() -> None:
        while not done.wait(interval):
            log(f"{label}: still running ({int(time.time() - started)}s)", kind="tool")

    thread = threading.Thread(target=beat, daemon=True, name="picaro-heartbeat")
    thread.start()
    try:
        yield
    finally:
        done.set()


class TargetOutputTicker(threading.Thread):
    """Mirror the debuggee's stdout/stderr to the activity log while a call blocks.

    lldb redirects the target's output to two temp files; a `run_until_event`
    can block for the whole timeout, and the operator should see what the
    target prints *while* it runs, not only in the stop result. Lines may be
    split across polls, so a partial line is held back until its newline
    arrives (a final partial line still shows up in the stop's output tail).
    """

    def __init__(self, session, interval: float = 0.25) -> None:
        super().__init__(daemon=True, name="picaro-output-ticker")
        self.session = session
        self.interval = interval
        self.stop_event = threading.Event()
        # Bind the two paths now, never follow the session: a `launch` swaps in
        # new files, and polling the old pair under the new name is misleading.
        self.paths = {
            "stdout": getattr(session, "out_path", None),
            "stderr": getattr(session, "err_path", None),
        }
        self.offsets = {"stdout": 0, "stderr": 0}
        self.partial = {"stdout": "", "stderr": ""}

    def run(self) -> None:
        while not self.stop_event.is_set():
            for stream in ("stdout", "stderr"):
                self.drain(stream, self.paths[stream])
            self.stop_event.wait(self.interval)

    def drain(self, stream: str, path) -> None:
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                handle.seek(self.offsets[stream])
                data = handle.read()
                self.offsets[stream] = handle.tell()
        except OSError:
            return
        if not data:
            return
        complete = (self.partial[stream] + data.decode("utf-8", "replace")).split("\n")
        self.partial[stream] = complete.pop()
        for line in complete:
            if line.strip():
                log(f"{stream}| {line.strip()}", kind="target")


@contextmanager
def streamed_target_output(session):
    """Run a blocking debugger call with the target's output mirrored live.

    Only for calls that leave the target running for a while (`run_until_event`,
    `step`, `run_artifact`'s own streaming): a `launch` swaps the output files
    mid-call, and its stop result carries their tails anyway.
    """
    ticker = TargetOutputTicker(session)
    ticker.start()
    try:
        yield
    finally:
        ticker.stop_event.set()
        ticker.join(timeout=2)


def first_line(text: str, limit: int = 200) -> str:
    lines = str(text).strip().splitlines()
    return lines[0][:limit] if lines else ""


# ---------------------------------------------------------------------------
# shared helpers (paths, picaro binary, subprocess, Defender)
# ---------------------------------------------------------------------------


def resolve_path(raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else (ROOT / path)


def resolve_executable(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    candidate = ROOT / path
    if candidate.is_file():
        return candidate
    if os.sep not in raw and "/" not in raw:
        found = shutil.which(raw)
        if found:
            return Path(found)
    return candidate


def picaro_bin() -> Path:
    override = os.environ.get("PICARO_BIN")
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise ToolError(f"PICARO_BIN points at a missing file: {override}")
    candidates = [
        ROOT / "target" / "release" / "picaro.exe",
        ROOT / "target" / "debug" / "picaro.exe",
    ]
    existing = [path for path in candidates if path.is_file()]
    if not existing:
        raise ToolError(
            "no picaro binary under target/{release,debug}; run `cargo build` first"
        )
    return max(existing, key=lambda path: path.stat().st_mtime)


def cap(text: str, limit: int = OUTPUT_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... truncated at {limit} characters ...]"


def clamp_timeout(value, default: int, low: int, high: int) -> int:
    try:
        seconds = int(value) if value is not None else default
    except (TypeError, ValueError):
        seconds = default
    return max(low, min(high, seconds))


def run(cmd, *, timeout: int, cwd: Path | None = None):
    try:
        return subprocess.run(
            [str(part) for part in cmd],
            cwd=str(cwd or ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        raise ToolError(
            f"timed out after {timeout}s (the direct child was killed; any "
            f"grandchildren may still be running)\n{cap(partial)}"
        ) from None
    except OSError as exc:
        raise ToolError(f"failed to start {cmd[0]}: {exc}") from None


def run_streaming(cmd, *, timeout: int, cwd: Path | None = None, label: str = "artifact"):
    """Run a child and mirror its output to the activity log, line by line.

    `run_artifact` can spend a minute with the payload running; the operator
    watching the console should see the output arrive instead of only the final
    result. Both pipes are drained by their own thread (a child that fills a
    pipe buffer would otherwise deadlock).
    """
    try:
        proc = subprocess.Popen(
            [str(part) for part in cmd],
            cwd=str(cwd or ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        raise ToolError(f"failed to start {cmd[0]}: {exc}") from None
    captured: dict[str, list] = {"stdout": [], "stderr": []}

    def pump(name: str) -> None:
        stream = getattr(proc, name)
        assert stream is not None
        for line in stream:
            captured[name].append(line)
            if line.strip():
                log(f"{label}| {line.strip()}", kind="target")

    threads = [
        threading.Thread(target=pump, args=(name,), daemon=True, name=f"picaro-{label}-{name}")
        for name in ("stdout", "stderr")
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    for thread in threads:
        thread.join(timeout=5)
    stdout, stderr = captured["stdout"], captured["stderr"]
    if timed_out:
        raise ToolError(
            f"timed out after {timeout}s (the direct child was killed; any "
            f"grandchildren may still be running)\n{cap(''.join(stdout) + ''.join(stderr))}"
        )
    return subprocess.CompletedProcess(
        [str(part) for part in cmd], proc.returncode, "".join(stdout), "".join(stderr)
    )


_DEFENDER_CACHE: dict = {"info": {}, "queried_at": 0.0}


def defender_info(*, refresh: bool = False) -> dict:
    now = time.time()
    if (
        not refresh
        and _DEFENDER_CACHE["queried_at"]
        and now - _DEFENDER_CACHE["queried_at"] < 30
    ):
        return _DEFENDER_CACHE["info"]
    info: dict = {}
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled,"
                " AntivirusEnabled, AMServiceEnabled, IsTamperProtected | Format-List",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        for line in (proc.stdout or "").splitlines():
            match = re.match(r"^([A-Za-z]+)\s*:\s*(.+?)\s*$", line)
            if match:
                raw = match.group(2)
                info[match.group(1)] = {"True": True, "False": False}.get(raw, raw)
    except (OSError, subprocess.TimeoutExpired):
        info = {}
    _DEFENDER_CACHE.update(info=info, queried_at=now)
    return info


def require_lab(tool: str) -> None:
    if not LAB_ENABLED:
        raise ToolError(
            f"{tool} is disabled: this server runs in analysis-only mode. "
            "Restart it with --lab (only on the isolated lab host, with "
            "Defender real-time protection off)."
        )


def require_real_time_off(tool: str):
    state = defender_info().get("RealTimeProtectionEnabled")
    if state is True:
        raise ToolError(
            f"{tool} refused: Windows Defender real-time protection is on. "
            "Executing loaders is a lab-host operation; disable real-time "
            "protection there and retry."
        )
    return state


def get_session() -> "debugger.Session":
    global SESSION
    if not debugger.bootstrap():
        raise ToolError(f"lldb is not available: {debugger.LLDB_ERROR}")
    if SESSION is None:
        # The session reports every event (launch, stops, breakpoints) and the
        # server turns those lines into the activity log.
        SESSION = debugger.Session(on_event=lambda message: log(message, kind="debug"))
    return SESSION


# ---------------------------------------------------------------------------
# tools: inert prep
# ---------------------------------------------------------------------------


_AUDIT_META_KEYS = (
    "report_schema",
    "binary",
    "size",
    "arch",
    "subsystem",
    "timestamp",
    "has_signature",
    "has_manifest",
    "overlay",
)
_AUDIT_FOCUS_KEYS = {
    "sections": ("sections",),
    "imports": ("imports",),
    "exports": ("exports",),
    "strings": ("strings",),
    "yara": ("yara",),
    "defender": ("defender",),
}


def apply_audit_focus(report: dict, focus: str) -> dict:
    """Trim a `picaro audit --json` report to the requested `focus` sections.

    `picaro audit --focus` only filters the *pretty* report; `--json` always
    emits the whole thing. The tool exposes the flag, so it trims the JSON here:
    the meta fields are always kept, recognised sections are added, and an
    unknown token contributes nothing -- mirroring the pretty renderer.
    """
    wanted = set()
    for part in str(focus).split(","):
        wanted.update(_AUDIT_FOCUS_KEYS.get(part.strip().lower(), ()))
    keep = set(_AUDIT_META_KEYS) | wanted
    return {key: value for key, value in report.items() if key in keep}


def tool_audit_file(args: dict):
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    cmd = [picaro_bin(), "audit", str(path), "--json", "-q", "--no-color"]
    focus = args.get("focus")
    if focus:
        cmd += ["--focus", str(focus)]
    if args.get("baseline"):
        cmd += ["--baseline", str(resolve_path(str(args["baseline"])))]
    proc = run(cmd, timeout=180)
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 3:
        return "REGRESSION (audit --baseline exited 3):\n" + cap(text)
    if proc.returncode != 0:
        raise ToolError(f"audit failed (exit {proc.returncode}):\n" + cap(text.strip()))
    if focus:
        # `--json` ignores `--focus`, so trim it here. Never with `baseline`: that
        # comparison is rendered by picaro itself and must pass through as-is.
        try:
            report = json.loads(text)
        except json.JSONDecodeError:
            report = None
        if isinstance(report, dict):
            text = json.dumps(apply_audit_focus(report, str(focus)), indent=2)
    return cap(text, JSON_LIMIT)


def tool_hash_file(args: dict):
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    digests = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),
        "md5": hashlib.md5(),
    }
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            size += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    return {
        "path": str(path),
        "size": size,
        **{name: digest.hexdigest() for name, digest in digests.items()},
    }


def tool_pe_info(args: dict):
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    try:
        import pefile
    except ImportError:
        raise ToolError("pefile is not installed (pip install pefile)") from None
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as exc:
        raise ToolError(f"not a PE file: {exc}") from None
    machine = pe.FILE_HEADER.Machine
    optional = pe.OPTIONAL_HEADER
    entry_rva = optional.AddressOfEntryPoint
    image_base = optional.ImageBase
    sections = []
    for section in pe.sections:
        flags = []
        characteristics = section.Characteristics
        if characteristics & 0x20000000:
            flags.append("execute")
        if characteristics & 0x80000000:
            flags.append("write")
        if characteristics & 0x40000000:
            flags.append("read")
        sections.append(
            {
                "name": section.Name.rstrip(b"\x00").decode("ascii", "replace"),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "flags": flags,
            }
        )
    machine_names = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
    return {
        "path": str(path),
        "machine": machine_names.get(machine, hex(machine)),
        "subsystem": optional.Subsystem,
        "image_base": hex(image_base),
        "entry_point_rva": hex(entry_rva),
        "entry_point_va": hex(image_base + entry_rva),
        "size_of_image": optional.SizeOfImage,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": sections,
    }


def tool_export_lookup(args: dict):
    """Resolve a module export to its RVA and, with a live session, to its address.

    System DLLs ship no symbol file offline, so `bp_set("ntdll!NtX")` stays
    pending; this reads the PE's export table instead and returns the address
    for an `@0x...` breakpoint.
    """
    module_name = str(args["module"])
    symbol = str(args["name"])
    base = None
    path = None
    with DEBUG_LOCK:
        if SESSION is not None and SESSION.has_session():
            found = SESSION.find_module(module_name)
            if found:
                base = found["base"]
                path = found["path"]
    if path is None:
        candidate = resolve_path(module_name)
        if not candidate.is_file():
            system_root = os.environ.get("SystemRoot", r"C:\Windows")
            candidate = Path(system_root) / "System32" / module_name
            if not candidate.is_file() and "." not in module_name:
                candidate = candidate.with_suffix(".dll")
        if not candidate.is_file():
            raise ToolError(f"module not loaded and not found on disk: {module_name}")
        path = str(candidate)
    try:
        import pefile
    except ImportError:
        raise ToolError("pefile is not installed (pip install pefile)") from None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except pefile.PEFormatError as exc:
        raise ToolError(f"not a PE file: {path}: {exc}") from None
    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exports is None:
        raise ToolError(f"{path} has no export table")
    wanted = symbol.encode("ascii", "replace")
    matches = []
    for entry in exports.symbols:
        if entry.name and entry.name == wanted:
            matches.append(entry.address)
    if not matches:
        raise ToolError(f"export not found: {symbol} in {path}")
    rva = matches[0]
    result = {
        "module": path,
        "name": symbol,
        "rva": hex(rva),
        "base": hex(base) if base is not None else None,
        "address": hex(base + rva) if base is not None else None,
    }
    if base is None:
        result["note"] = "no live session: no base/address, only the RVA"
    return result


def tool_disassemble_file(args: dict):
    """Static disassembly of a PE file (entry, address, RVA or export name)."""
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    count = max(1, min(int(args.get("count", 24)), 200))
    at = args.get("at")
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    except ImportError:
        raise ToolError("pefile is not installed (pip install pefile)") from None
    except pefile.PEFormatError as exc:
        raise ToolError(f"not a PE file: {exc}") from None
    if at is None:
        start_va = base + entry_rva
    elif str(at).startswith("+"):
        start_va = base + int(str(at)[1:], 0)
    elif str(at).startswith("0x"):
        start_va = int(str(at), 0)
    else:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        wanted = str(at).encode("ascii", "replace")
        found_rva = None
        if exports is not None:
            for entry in exports.symbols:
                if entry.name == wanted:
                    found_rva = entry.address
                    break
        if found_rva is None:
            raise ToolError(f"not an address and no such export: {at!r}")
        start_va = base + found_rva
    objdump = shutil.which("llvm-objdump.exe") or shutil.which("llvm-objdump")
    if not objdump:
        raise ToolError(
            "llvm-objdump not found in PATH (it ships with the scoop llvm install)"
        )
    window = max(0x100, count * 15)
    proc = run(
        [
            objdump,
            "-d",
            "--x86-asm-syntax=intel",
            f"--start-address={hex(start_va)}",
            f"--stop-address={hex(start_va + window)}",
            str(path),
        ],
        timeout=120,
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    instructions = []
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+\S", line)
        if not match:
            continue
        if int(match.group(1), 16) < start_va:
            continue
        instructions.append(line.rstrip())
        if len(instructions) >= count:
            break
    if not instructions:
        return {
            "file": str(path),
            "start": hex(start_va),
            "instructions": [],
            "note": "nothing decoded in the window",
            "raw": cap(text.strip(), 2000),
        }
    return {"file": str(path), "start": hex(start_va), "instructions": instructions}


def tool_strings_file(args: dict):
    """ASCII + UTF-16LE strings with file offsets (triage, not the audit's triage)."""
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    minimum = max(4, min(int(args.get("min_length", 6)), 64))
    encoding = str(args.get("encoding") or "both")
    limit = max(1, min(int(args.get("limit", 200)), 2000))
    data = path.read_bytes()
    found: list = []
    if encoding in ("both", "ascii"):
        pattern = re.compile(("[\\x20-\\x7e]{%d,}" % minimum).encode("ascii"))
        for match in pattern.finditer(data):
            found.append((match.start(), "ascii", match.group().decode("ascii", "replace")))
    if encoding in ("both", "utf16"):
        pattern = re.compile(("(?:[\\x20-\\x7e]\\x00){%d,}" % minimum).encode("ascii"))
        for match in pattern.finditer(data):
            found.append(
                (match.start(), "utf16", match.group().decode("utf-16le", "replace"))
            )
    found.sort(key=lambda item: item[0])
    unique = []
    seen = set()
    for offset, kind, value in found:
        if value in seen:
            continue
        seen.add(value)
        unique.append({"offset": hex(offset), "encoding": kind, "value": value})
        if len(unique) >= limit:
            break
    return {
        "path": str(path),
        "size": len(data),
        "min_length": minimum,
        "raw_count": len(found),
        "returned": len(unique),
        "truncated": len(unique) >= limit,
        "strings": unique,
    }


def tool_yara_scan(args: dict):
    """Scan a file with the yara CLI.

    The CLI takes rule *files*, never a directory (it fails with "could not
    open file"), so a directory is enumerated to .yar/.yara files here -- the
    same thing picaro's own audit does.
    """
    path = resolve_path(str(args["path"]))
    if not path.is_file():
        raise ToolError(f"no such file: {path}")
    rules = args.get("rules")
    rules_path = (
        resolve_path(str(rules))
        if rules
        else (ROOT / "src" / "audit" / "yara" / "rules")
    )
    if not rules_path.exists():
        raise ToolError(f"rules not found: {rules_path}")
    if rules_path.is_dir():
        rule_files = sorted(
            candidate
            for candidate in rules_path.rglob("*")
            if candidate.is_file() and candidate.suffix.lower() in (".yar", ".yara")
        )
    else:
        rule_files = [rules_path]
    if not rule_files:
        raise ToolError(f"no .yar/.yara rule files under {rules_path}")
    override = os.environ.get("PICARO_YARA")
    yara = (
        shutil.which(override)
        if override
        else (shutil.which("yara.exe") or shutil.which("yara"))
    )
    if not yara:
        raise ToolError(
            "yara is not installed; install the CLI (e.g. `scoop install yara`) "
            "to scan with custom or community rules"
        )
    cmd = [yara]
    if args.get("print_strings"):
        cmd.append("-s")
    cmd += [str(rule) for rule in rule_files]
    cmd.append(str(path))
    proc = run(cmd, timeout=clamp_timeout(args.get("timeout"), 120, 5, 900))
    text = (proc.stdout or "") + (proc.stderr or "")
    matches = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    return {
        "file": str(path),
        "rule_files": [str(rule) for rule in rule_files],
        "exit_code": proc.returncode,
        "matches": matches,
        "output": cap(text.strip()) if not matches else None,
    }


def run_picaro(subcommand: list, *, label: str, timeout: int = 60) -> str:
    """Run `picaro <subcommand...>` and return its combined output.

    A non-zero exit becomes a ToolError carrying picaro's own message, so the agent
    reads what the CLI said instead of a bare exit code.
    """
    proc = run([picaro_bin(), *subcommand, "-q", "--no-color"], timeout=timeout)
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise ToolError(f"{label} failed (exit {proc.returncode}):\n" + cap(text.strip()))
    return cap(text)


def tool_techniques_list(args: dict):
    return run_picaro(["techniques", "list"], label="techniques list")


def tool_technique_show(args: dict):
    name = str(args["name"]).strip()
    if not name or any(ch in name for ch in "/\\:"):
        raise ToolError(f"name must be a technique key (got {args.get('name')!r})")
    return run_picaro(
        ["techniques", "show", name, "--raw", "--no-pager"],
        label=f"techniques show {name}",
    )


def tool_techniques_validate(args: dict):
    # `picaro techniques validate` is a CI helper that never fails: the verdict is
    # the text itself, so it is returned rather than turned into an error.
    proc = run([picaro_bin(), "techniques", "validate", "-q", "--no-color"], timeout=60)
    return cap((proc.stdout or "") + (proc.stderr or ""))


def named_stage_dir(output: str, name: str) -> Path | None:
    """The `build/<name>` directory a named build reported on its `scratch` line.

    The CLI prints the resolved path, so a `PICARO_BUILD_DIR` override is honored;
    fall back to `<repo>/build/<name>` when the line is missing.
    """
    match = re.search(r"^\s*scratch\s+(\S.*?)\s*$", output, re.MULTILINE)
    if match:
        candidate = Path(match.group(1))
        if candidate.is_dir():
            return candidate
    candidate = ROOT / "build" / name
    return candidate if candidate.is_dir() else None


def tool_build_plan(args: dict):
    plan = resolve_path(str(args["plan"]))
    if not plan.is_file():
        raise ToolError(f"no such plan: {plan}")
    name = args.get("name")
    if name is not None:
        name = str(name).strip()
        if not name or name in (".", "..") or any(ch in name for ch in "/\\:"):
            raise ToolError(f"name must be a single directory name (got {args.get('name')!r})")
    cmd = [picaro_bin(), "build", str(plan), "-q", "--no-color"]
    if args.get("dry_run"):
        cmd.append("--dry-run")
    if args.get("debug"):
        cmd.append("--debug")
    if name:
        cmd += ["--build-name", name]
    cmd += [str(extra) for extra in (args.get("args") or [])]
    with heartbeat(f"build {plan.name}"):
        proc = run(
            cmd, timeout=clamp_timeout(args.get("timeout"), DEFAULT_BUILD_TIMEOUT, 10, 1800)
        )
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise ToolError(f"build failed (exit {proc.returncode}):\n" + cap(text.strip()))
    result: dict = {"exit_code": 0, "output": cap(text)}
    if not args.get("dry_run"):
        # The engine stages each build under build/<name>/ (a `name` was given)
        # or build/run-<pid>-<timestamp>/ (default), keeping out.exe + out.pdb +
        # main.rs together. Debug that intermediate, not the dist/ copy: the PDB
        # is referenced by bare name (out.pdb) and lldb only resolves it next to
        # the executable.
        stage = named_stage_dir(text, name) if name else None
        if stage is None:
            runs = [path for path in (ROOT / "build").glob("run-*") if path.is_dir()]
            stage = max(runs, key=lambda path: path.stat().st_mtime) if runs else None
        if stage is not None:
            if name:
                result["build_name"] = name
            stub_exe = stage / "out.exe"
            stub_source = stage / "main.rs"
            if stub_exe.is_file():
                result["stub_exe"] = str(stub_exe)
            if stub_source.is_file():
                result["stub_source"] = str(stub_source)
    return result


def tool_defender_status(args: dict):
    info = defender_info(refresh=bool(args.get("refresh")))
    return {
        "defender": info or "unavailable (Get-MpComputerStatus did not answer)",
        "lab_gate": {
            "lab_mode": LAB_ENABLED,
            "execution_tools": bool(LAB_ENABLED),
        },
    }


def tool_activity_log(args: dict):
    """The session transcript: tool calls, debugger stops and target output."""
    limit = max(1, min(int(args.get("limit", 50)), 500))
    kind = args.get("kind")
    with LOG_LOCK:
        events = list(EVENTS)
    buffered = len(events)
    if kind:
        events = [event for event in events if event["kind"] == kind]
    if args.get("since") is not None:
        since = int(args["since"])
        events = [event for event in events if event["seq"] > since]
    selected = events[-limit:]
    return {
        "log_file": str(LOG_PATH) if LOG_PATH else None,
        "log_url": "GET /log?tail=<n> on this server",
        "events_buffered": buffered,
        "events_returned": len(selected),
        "note": (
            "newest last; kinds: tool (a call and its result), debug (launch, stops, "
            "breakpoints), target (a line the debuggee printed), error, note"
        ),
        "events": selected,
    }


# ---------------------------------------------------------------------------
# tools: execution (no debugger)
# ---------------------------------------------------------------------------


def tool_run_artifact(args: dict):
    require_lab("run_artifact")
    defender_state = require_real_time_off("run_artifact")
    exe = resolve_executable(str(args["path"]))
    if not exe.is_file():
        raise ToolError(f"no such executable: {exe}")
    cmd = [exe] + [str(extra) for extra in (args.get("args") or [])]
    cwd = resolve_path(str(args["cwd"])) if args.get("cwd") else ROOT
    timeout = clamp_timeout(args.get("timeout"), DEFAULT_RUN_TIMEOUT, 1, 600)
    started = time.time()
    proc = run_streaming(cmd, timeout=timeout, cwd=cwd, label=exe.name)
    result = {
        "path": str(exe),
        "args": [str(extra) for extra in (args.get("args") or [])],
        "exit_code": proc.returncode,
        "elapsed_s": round(time.time() - started, 2),
        "stdout": cap(proc.stdout or ""),
        "stderr": cap(proc.stderr or ""),
    }
    if defender_state is None:
        result["warning"] = (
            "Defender real-time protection state is unknown (query failed)."
        )
    if args.get("expect") is not None:
        combined = (proc.stdout or "") + (proc.stderr or "")
        result["expect"] = args["expect"]
        result["expect_found"] = str(args["expect"]) in combined
    return result


# ---------------------------------------------------------------------------
# tools: debugger
# ---------------------------------------------------------------------------


def tool_debug_launch(args: dict):
    require_lab("debug_launch")
    require_real_time_off("debug_launch")
    exe = resolve_executable(str(args["path"]))
    if not exe.is_file():
        raise ToolError(f"no such executable: {exe}")
    cwd = resolve_path(str(args["cwd"])) if args.get("cwd") else None
    args_list = [str(extra) for extra in (args.get("args") or [])]
    with DEBUG_LOCK:
        session = get_session()
        stop = session.launch(
            exe,
            args_list,
            cwd,
            bool(args.get("stop_at_entry", True)),
        )
    return stop


def tool_debug_attach(args: dict):
    require_lab("debug_attach")
    pid = args.get("pid")
    name = args.get("name")
    if pid is None and not name:
        raise ToolError("debug_attach needs `pid` or `name`")
    with DEBUG_LOCK:
        session = get_session()
        stop = session.attach(pid=int(pid) if pid is not None else None, name=name)
    return stop


def tool_debug_close(args: dict):
    with DEBUG_LOCK:
        if SESSION is None:
            return {"session": None, "note": "there was no active session"}
        return SESSION.close(kill=bool(args.get("kill", True)))


def tool_debug_status(args: dict):
    with DEBUG_LOCK:
        if SESSION is None or not SESSION.has_session():
            return {"session": None}
        session = SESSION
        try:
            info = session.stop_info()
        except debugger.DebugError as exc:
            info = {"error": str(exc)}
        info["path"] = session.path
        return info


def tool_bp_set(args: dict):
    require_lab("bp_set")
    with DEBUG_LOCK:
        session = get_session()
        return session.breakpoint_add(
            str(args["spec"]),
            hardware=bool(args.get("hardware")),
            condition=args.get("condition"),
        )


def tool_bp_list(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return {"breakpoints": session.breakpoint_list()}


def tool_bp_delete(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.breakpoint_delete(int(args["id"]))


def tool_bp_enable(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.breakpoint_enable(int(args["id"]), bool(args.get("enabled", True)))


def tool_run_until_event(args: dict):
    require_lab("run_until_event")
    timeout = clamp_timeout(args.get("timeout_s"), DEFAULT_CONTINUE_TIMEOUT, 1, 600)
    with DEBUG_LOCK:
        session = get_session()
        with streamed_target_output(session):
            return session.continue_until_event(timeout)


def tool_step(args: dict):
    require_lab("step")
    timeout = clamp_timeout(args.get("timeout_s"), DEFAULT_STEP_TIMEOUT, 1, 120)
    with DEBUG_LOCK:
        session = get_session()
        with streamed_target_output(session):
            return session.step(str(args.get("kind") or "over"), timeout)


def tool_registers(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.registers(args.get("thread_id"), args.get("names"))


def tool_read_memory(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.read_memory(args["address"], int(args.get("size", 64)))


def tool_write_memory(args: dict):
    require_lab("write_memory")
    with DEBUG_LOCK:
        session = get_session()
        return session.write_memory(args["address"], str(args["hex_bytes"]))


def tool_memory_scan(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.memory_scan(
            str(args["pattern"]),
            args.get("start"),
            int(args.get("max_results", 32)),
            float(args.get("budget_s", 5.0)),
        )


def tool_stack(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.stack(args.get("thread_id"), int(args.get("count", 20)))


def tool_threads(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return {"threads": session.threads()}


def tool_select_thread(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.select_thread(int(args["thread_id"]))


def tool_modules(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return {"modules": session.modules(args.get("filter"))}


def tool_disassemble(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.disassemble(args.get("address"), int(args.get("count", 16)))


def tool_evaluate(args: dict):
    with DEBUG_LOCK:
        session = get_session()
        return session.evaluate(str(args["expression"]))


# ---------------------------------------------------------------------------
# MCP plumbing
# ---------------------------------------------------------------------------

TOOLS_INERT = [
    {
        "name": "audit_file",
        "description": (
            "Static audit of a PE with `picaro audit --json` (header, sections, entropy, "
            "imports/exports, string triage, YARA, Defender verdict). `focus` trims the "
            "report to the named sections (plus the meta fields). Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "PE path, repo-relative or absolute."},
                "focus": {"type": "string", "description": 'Comma-separated sections (sections, imports, exports, strings, yara, defender), e.g. "imports,strings".'},
                "baseline": {"type": "string", "description": "Previous --json report; a regression comes back prefixed with REGRESSION."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "hash_file",
        "description": "sha256, sha1, md5 and size for a file. Inert.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "pe_info",
        "description": (
            "Minimal PE facts: machine, entry point RVA/VA (the payload OEP for breakpoint "
            "math), image base, sections with flags. Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "export_lookup",
        "description": (
            "Resolve a module export (system DLL, payload, stub) to its RVA and, with a "
            "live session, to its address. System DLLs ship no symbols offline, so "
            "`bp_set(\"ntdll!NtX\")` stays pending: use this and then bp_set(\"@<address>\"). "
            "Inert; reads the PE on disk (and the session's module list when there is one)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "\"ntdll\" (loaded or System32) or a path."},
                "name": {"type": "string", "description": "Export name, e.g. NtAllocateVirtualMemory."},
            },
            "required": ["module", "name"],
        },
    },
    {
        "name": "disassemble_file",
        "description": (
            "Static disassembly (Intel syntax, via llvm-objdump) of a PE file: at the "
            "entry point by default, or at `at` = an absolute VA (0x...), an RVA "
            "(+0x...) or an export name. Inert. For symbol-level disassembly of a --debug "
            "stub use the live session (lldb knows the PDB)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "at": {"type": "string", "description": "0x<VA>, +0x<RVA>, or an export name; default entry point."},
                "count": {"type": "integer", "description": "Instructions to return; default 24."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "strings_file",
        "description": (
            "ASCII and UTF-16LE strings with file offsets, from any file (not only PEs). "
            "For the audit's curated triage of a PE use audit_file; this is the raw view. Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "min_length": {"type": "integer", "description": "Default 6."},
                "encoding": {"type": "string", "enum": ["both", "ascii", "utf16"]},
                "limit": {"type": "integer", "description": "Max strings returned; default 200."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "yara_scan",
        "description": (
            "Scan a file with the yara CLI. `rules` may be a rule file or a directory "
            "(directories are enumerated to .yar/.yara files; the CLI itself rejects "
            "a directory argument). Defaults to the repo's rules under "
            "src/audit/yara/rules/. `print_strings` adds -s (matched strings and "
            "offsets). Needs yara on PATH (`scoop install yara`). Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "rules": {"type": "string", "description": "Rule file or directory; default = the repo's rules."},
                "print_strings": {"type": "boolean", "description": "Add -s to report matched strings."},
                "timeout": {"type": "integer", "description": "Seconds; default 120."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "techniques_list",
        "description": (
            "List the technique registry with `picaro techniques list`: key, category, "
            "stability, ATT&CK id and a one-line summary per technique. Inert."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "technique_show",
        "description": (
            "A technique's full README (`picaro techniques show <name> --raw`): what it "
            "does, its plan keys and its notes. Use it to learn a technique before "
            "reading or editing its fragment. Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Technique key, e.g. reflective_loading."}
            },
            "required": ["name"],
        },
    },
    {
        "name": "techniques_validate",
        "description": (
            "Validate the technique registry (`picaro techniques validate`): keys, "
            "fragments and loader features. Never fails; the verdict is the text. Inert."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "build_plan",
        "description": (
            "Run `picaro build <plan.yaml>`. Use debug=true for a debug stub: techniques "
            "log, symbols/source paths are kept, and the generated source is under "
            "build/<name>/main.rs (a `name`, stable across runs) or build/run-*/main.rs "
            "(default, unique). Returns stub_exe/stub_source for debug_launch."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Positional $arg.N$ values."},
                "debug": {"type": "boolean"},
                "name": {"type": "string", "description": "Stage the build under build/<name> (stable path for debugging); the CLI flag is --build-name."},
                "dry_run": {"type": "boolean"},
                "timeout": {"type": "integer", "description": "Seconds; default 600."},
            },
            "required": ["plan"],
        },
    },
    {
        "name": "defender_status",
        "description": "Windows Defender state plus this server's lab gate. Inert.",
        "inputSchema": {
            "type": "object",
            "properties": {"refresh": {"type": "boolean"}},
        },
    },
    {
        "name": "activity_log",
        "description": (
            "The server's activity transcript, newest last: every tool call and its "
            "result (`tool`), every session event such as launch/stop/breakpoint "
            "(`debug`), every line the target printed (`target`), plus `error`/`note`. "
            "Use it to report what a session actually did (or to check what happened "
            "while another call was blocking). The same lines are mirrored to a "
            "session log file (`log_file`) and to the console. Inert."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Events returned, newest last; default 50, max 500."},
                "kind": {
                    "type": "string",
                    "enum": ["tool", "debug", "target", "error", "note"],
                    "description": "Only events of this kind.",
                },
                "since": {"type": "integer", "description": "Only events with seq greater than this (poll incrementally)."},
            },
        },
    },
]

TOOLS_EXEC = [
    {
        "name": "run_artifact",
        "description": (
            "LAB ONLY. Run a PE without a debugger (control run): exit code, stdout, "
            "stderr, optional `expect` substring. Compare against a debug_launch run to "
            "see what a debugger changes (anti-debug behavior)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "timeout": {"type": "integer", "description": "Seconds; default 60, max 600."},
                "expect": {"type": "string"},
            },
            "required": ["path"],
        },
    },
]

TOOLS_DEBUG = [
    {
        "name": "debug_launch",
        "description": (
            "LAB ONLY. Start a target under lldb and return the first stop (entry by "
            "default). stdout/stderr are captured and included in every stop result. "
            "Spaces in args are fine; do NOT include the program itself in `args`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "stop_at_entry": {"type": "boolean", "description": "Default true."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "debug_attach",
        "description": "LAB ONLY. Attach to a running process by pid or name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "name": {"type": "string", "description": "Process name, e.g. svchost.exe."},
            },
        },
    },
    {
        "name": "debug_close",
        "description": "Close the session: kill the process (default) or detach, then drop the target.",
        "inputSchema": {
            "type": "object",
            "properties": {"kill": {"type": "boolean", "description": "Default true."}},
        },
    },
    {
        "name": "debug_status",
        "description": "Current session summary (path, pid, state, stop detail). No session returns null.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bp_set",
        "description": (
            "Set a breakpoint. Spec forms: `module!symbol` (ntdll!NtAllocateVirtualMemory), "
            "`symbol` (step_0::run; a name with no match falls back to a regex), "
            "`re:<regex>`, `file.rs:123` (generated source under build/run-*/), "
            "`+0x<rva>` (main-module RVA), `@0x<addr>`, or plain `0x<addr>`. Pending "
            "(0 locations) is fine: lldb resolves when the module loads."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "spec": {"type": "string"},
                "hardware": {"type": "boolean", "description": "Hardware breakpoint (address or name)."},
                "condition": {"type": "string", "description": "lldb condition expression."},
            },
            "required": ["spec"],
        },
    },
    {
        "name": "bp_list",
        "description": "List breakpoints with ids, specs, hit counts and resolved locations.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bp_delete",
        "description": "Delete a breakpoint by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"],
        },
    },
    {
        "name": "bp_enable",
        "description": "Enable or disable a breakpoint by id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "enabled": {"type": "boolean", "description": "Default true."},
            },
            "required": ["id"],
        },
    },
    {
        "name": "run_until_event",
        "description": (
            "Continue and return the next stop: breakpoint, step, exception, signal, "
            "entry, exited, crashed, or timeout (watchdog interrupt; the process is left "
            "stopped and usable). Never blocks longer than timeout_s (1..600, default 30)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"timeout_s": {"type": "integer"}},
        },
    },
    {
        "name": "step",
        "description": "Step the selected thread: over, into, out, or a single instruction (insn).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["over", "into", "out", "insn"]},
                "timeout_s": {"type": "integer"},
            },
        },
    },
    {
        "name": "registers",
        "description": "Registers of the selected (or given) thread's top frame.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "thread_id": {"type": "integer"},
                "names": {"type": "array", "items": {"type": "string"}, "description": "Optional subset, e.g. [rip, rsp, rax]."},
            },
        },
    },
    {
        "name": "read_memory",
        "description": "Read memory. `address` accepts hex, decimal or a register name (rip, rax). Max 64 KiB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "size": {"type": "integer", "description": "Default 64."},
            },
            "required": ["address"],
        },
    },
    {
        "name": "write_memory",
        "description": "LAB ONLY. Patch memory (hex bytes, e.g. \"90 90\"); returns a readback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "hex_bytes": {"type": "string"},
            },
            "required": ["address", "hex_bytes"],
        },
    },
    {
        "name": "memory_scan",
        "description": (
            "Search readable memory: `ascii:`-prefixed (default), `hex:`-prefixed (\"hex:4d 5a\") "
            "or a raw literal. Optional `start` address limits the scan to that region. "
            "Use it to locate a mapped payload (scan for `MZ` after the allocation)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "start": {"type": "string"},
                "max_results": {"type": "integer", "description": "Default 32."},
                "budget_s": {"type": "number", "description": "Time budget in seconds; default 5."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "stack",
        "description": "Backtrace of the selected (or given) thread.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "thread_id": {"type": "integer"},
                "count": {"type": "integer", "description": "Default 20."},
            },
        },
    },
    {
        "name": "threads",
        "description": "List threads with stop reason and pc; marks the selected one.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "select_thread",
        "description": "Select a thread by id (affects step/registers/stack defaults).",
        "inputSchema": {
            "type": "object",
            "properties": {"thread_id": {"type": "integer"}},
            "required": ["thread_id"],
        },
    },
    {
        "name": "modules",
        "description": "List loaded modules with base addresses (optional name filter).",
        "inputSchema": {
            "type": "object",
            "properties": {"filter": {"type": "string"}},
        },
    },
    {
        "name": "disassemble",
        "description": "Intel-syntax disassembly at an address (default: pc).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "count": {"type": "integer", "description": "Default 16."},
            },
        },
    },
    {
        "name": "evaluate",
        "description": "Evaluate an expression in the selected frame (e.g. (void*)GetModuleHandleA(0)).",
        "inputSchema": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
]

HANDLERS = {
    "audit_file": tool_audit_file,
    "hash_file": tool_hash_file,
    "pe_info": tool_pe_info,
    "export_lookup": tool_export_lookup,
    "disassemble_file": tool_disassemble_file,
    "strings_file": tool_strings_file,
    "yara_scan": tool_yara_scan,
    "techniques_list": tool_techniques_list,
    "technique_show": tool_technique_show,
    "techniques_validate": tool_techniques_validate,
    "build_plan": tool_build_plan,
    "defender_status": tool_defender_status,
    "activity_log": tool_activity_log,
    "run_artifact": tool_run_artifact,
    "debug_launch": tool_debug_launch,
    "debug_attach": tool_debug_attach,
    "debug_close": tool_debug_close,
    "debug_status": tool_debug_status,
    "bp_set": tool_bp_set,
    "bp_list": tool_bp_list,
    "bp_delete": tool_bp_delete,
    "bp_enable": tool_bp_enable,
    "run_until_event": tool_run_until_event,
    "step": tool_step,
    "registers": tool_registers,
    "read_memory": tool_read_memory,
    "write_memory": tool_write_memory,
    "memory_scan": tool_memory_scan,
    "stack": tool_stack,
    "threads": tool_threads,
    "select_thread": tool_select_thread,
    "modules": tool_modules,
    "disassemble": tool_disassemble,
    "evaluate": tool_evaluate,
}


def tool_schemas() -> list:
    schemas = list(TOOLS_INERT)
    if LAB_ENABLED:
        schemas += TOOLS_EXEC + TOOLS_DEBUG
    return schemas


def summarize(result) -> str:
    """One line for the console log."""
    if isinstance(result, dict):
        parts = []
        kind = result.get("kind") or result.get("state")
        if kind:
            parts.append(str(kind))
        for key in ("pid", "id", "exit_status", "selected", "written", "session"):
            if key in result and result[key] is not None:
                parts.append(f"{key}={result[key]}")
        for key in ("breakpoints", "threads", "modules", "frames", "matches", "events"):
            if isinstance(result.get(key), list):
                parts.append(f"{key}={len(result[key])}")
        return " ".join(parts) or "ok"
    text = str(result).strip().splitlines()
    return text[0][:120] if text else "ok"


def handle_message(message: dict):
    method = message.get("method")
    if method == "initialize":
        params = message.get("params") or {}
        return {
            "protocolVersion": params.get("protocolVersion") or PROTOCOL_FALLBACK,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": tool_schemas()}
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            return {"content": [{"type": "text", "text": f"unknown tool: {name!r}"}], "isError": True}
        started = time.time()
        # The request line is what tells the operator (and the transcript) what
        # the agent is doing; the result line follows when the call returns.
        log(f"-> {name} {format_arguments(arguments)}".rstrip(), kind="tool")
        try:
            result = handler(arguments)
        except ToolError as exc:
            log(
                f"<- {name} refused ({time.time() - started:.2f}s): {first_line(exc)}",
                kind="error",
                level="warning",
            )
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        except debugger.DebugError as exc:
            log(
                f"<- {name} debug error ({time.time() - started:.2f}s): {first_line(exc)}",
                kind="error",
                level="warning",
            )
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        except Exception as exc:  # noqa: BLE001 - a tool bug must not kill the server
            traceback.print_exc(file=sys.stderr)
            log(f"<- {name} internal error: {exc!r}", kind="error", level="error")
            return {"content": [{"type": "text", "text": f"internal error: {exc!r}"}], "isError": True}
        text = result if isinstance(result, str) else json.dumps(result, indent=2)
        elapsed = time.time() - started
        log(f"<- {name} ok ({elapsed:.2f}s): {summarize(result)}", kind="tool")
        return {"content": [{"type": "text", "text": text}], "isError": False}
    raise RpcError(-32601, f"method not found: {method!r}")


def rpc_response(message: dict) -> dict:
    try:
        return {"jsonrpc": "2.0", "id": message["id"], "result": handle_message(message)}
    except RpcError as exc:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": exc.code, "message": exc.message},
        }
    except Exception as exc:  # noqa: BLE001 - never kill the loop
        traceback.print_exc(file=sys.stderr)
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32603, "message": f"internal error: {exc!r}"},
        }


def log_tail(limit: int = 200) -> str:
    """Last `limit` lines of the session log file (for `GET /log`)."""
    if LOG_PATH is None or not LOG_PATH.is_file():
        return "no log file for this run\n"
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"cannot read {LOG_PATH}: {exc}\n"
    return "\n".join(lines[-max(1, min(limit, 5000)):]) + "\n"


def status_page() -> str:
    session_line = "none"
    with DEBUG_LOCK:
        if SESSION is not None and SESSION.has_session():
            try:
                info = SESSION.stop_info()
                session_line = (
                    f"{SESSION.path} pid={info.get('pid')} state={info.get('state')}"
                    f" kind={info.get('kind')}"
                )
            except Exception as exc:  # noqa: BLE001 - status page only
                session_line = f"error: {exc}"
    return (
        f"{SERVER_NAME} {SERVER_VERSION}\n"
        f"lldb: {debugger.version_string()}\n"
        f"lab: {'ON' if LAB_ENABLED else 'off'}\n"
        f"tools: {len(tool_schemas())}\n"
        f"session: {session_line}\n"
        f"log: {LOG_PATH if LOG_PATH else 'off'}  (GET /log?tail=200)\n"
        "endpoint: POST /mcp (MCP streamable HTTP)\n"
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "picaro-debugger-mcp"

    def log_message(self, fmt, *args):  # silence the default access log
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_rpc(self, response, message_id) -> None:
        body = json.dumps(response, ensure_ascii=False).encode("utf-8")
        accept = self.headers.get("Accept") or ""
        if "text/event-stream" in accept and "application/json" not in accept:
            payload = b"data: " + body + b"\n\n"
            self._send(200, payload, "text/event-stream")
        else:
            self._send(200, body, "application/json")

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path, _, query = self.path.partition("?")
        if path in ("/", "/status"):
            self._send(200, status_page().encode("utf-8"), "text/plain; charset=utf-8")
        elif path == "/log":
            tail = 200
            for piece in query.split("&"):
                key, _, value = piece.partition("=")
                if key == "tail" and value.isdigit():
                    tail = int(value)
            self._send(200, log_tail(tail).encode("utf-8"), "text/plain; charset=utf-8")
        elif path == "/mcp":
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/mcp":
            self._send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"parse error: {exc}"},
            }
            self._send_rpc(response, None)
            return
        if isinstance(payload, list):
            responses = [
                rpc_response(item)
                for item in payload
                if isinstance(item, dict) and "id" in item
            ]
            if not responses:
                self._send(202, b"", "application/json")
                return
            self._send_rpc(responses, None)
            return
        if isinstance(payload, dict) and "method" in payload and "id" not in payload:
            # Notification (e.g. notifications/initialized): 202, no body.
            if payload.get("method") not in ("notifications/initialized",):
                log(f"notification: {payload.get('method')}")
            self._send(202, b"", "application/json")
            return
        if isinstance(payload, dict) and "method" in payload:
            self._send_rpc(rpc_response(payload), payload.get("id"))
            return
        response = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "invalid request"},
        }
        self._send_rpc(response, None)


def open_log_file(override: str | None) -> Path:
    """The transcript file the console log is mirrored to.

    Default `build/mcp-session-<timestamp>.log`: gitignored, next to the staged
    builds it talks about, and easy to hand to someone else as evidence.
    """
    if override:
        path = resolve_path(override)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    directory = ROOT / "build"
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        directory = Path(tempfile.gettempdir())
    return directory / f"mcp-session-{time.strftime('%Y%m%d-%H%M%S')}.log"


def main() -> int:
    parser = argparse.ArgumentParser(description="picaro-debugger MCP server (HTTP)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="port (default 8787)")
    parser.add_argument("--lab", action="store_true", help="enable execution and debugger tools")
    parser.add_argument(
        "--log-file",
        default=os.environ.get("PICARO_MCP_LOG"),
        help="mirror the console log here (default build/mcp-session-<timestamp>.log)",
    )
    parser.add_argument("--no-log", action="store_true", help="write no log file")
    options = parser.parse_args()

    # picaro's output carries unicode (its UI glyphs); make the console pipe safe.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - non-reconfigurable stream
            pass

    global LAB_ENABLED, LOG_PATH
    LAB_ENABLED = LAB_ENABLED or options.lab
    if not options.no_log:
        LOG_PATH = open_log_file(options.log_file)

    debugger.bootstrap()
    print(f"{SERVER_NAME} {SERVER_VERSION}")
    print(f"  lldb:    {debugger.version_string()}")
    print(
        "  lab:     "
        + (
            "ON -- execution and debugger tools enabled"
            if LAB_ENABLED
            else "off -- inert tools only (pass --lab to enable the rest)"
        )
    )
    print(f"  tools:   {len(tool_schemas())}")
    print(f"  url:     http://{options.host}:{options.port}/mcp")
    print(f"  log:     {LOG_PATH if LOG_PATH else 'off'}  (GET /log?tail=200)")
    print("  console: this window is the live log; Ctrl+C stops the server")
    print(flush=True)
    log(
        f"{SERVER_NAME} {SERVER_VERSION} started: lab={'on' if LAB_ENABLED else 'off'}, "
        f"tools={len(tool_schemas())}, log={LOG_PATH or 'off'}"
    )

    server = ThreadingHTTPServer((options.host, options.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("", flush=True)
        log("interrupted; closing the session")
    finally:
        with DEBUG_LOCK:
            if SESSION is not None:
                SESSION.kill_on_shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

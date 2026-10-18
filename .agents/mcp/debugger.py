"""lldb session machinery for the picaro-debugger MCP server.

Every design choice here was measured, not guessed (the spike lives in the
session memory / `.memory.md`):

  * **Sync mode only.** With this LLDB build (23.1.2, Windows), async mode
    never delivers a usable stop context: 0 threads, stale stop ids, "process
    is running" on memory reads. Sync mode returns from Launch/Continue/Step
    with everything valid, so the session is a plain request/response object.
  * **Timeouts are a watchdog thread** calling ``SBProcess.SendAsyncInterrupt``
    (``SBProcess.Stop()`` from another thread does nothing here). A fired
    watchdog stops the process inside ntdll's DbgBreakPoint; the server labels
    that result ``timeout``.
  * **SBLaunchInfo argv must NOT include argv[0].** This lldb prepends the
    image, so ``["python.exe", "-m", ...]`` becomes ``python.exe python.exe -m
    ...`` and the debuggee misbehaves in ways that look like crashes (exit 1,
    "parsing python.exe as a script").
  * **stdio is redirected** (stdin NUL, stdout/stderr to temp files). Debuggees
    otherwise die on their first write, and the redirected files double as the
    artifact's output capture: every stop result includes their tails (and the
    server's output ticker mirrors them live -- see `out_path`/`err_path`).
  * **Every session event is reported to `on_event`** (launch, stops,
    breakpoints, memory writes, close). The server turns those lines into its
    activity log, so an operator watching the console sees the session unfold;
    a standalone caller can simply not pass the callback.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

LLDB = None
LLDB_ERROR = ""


class DebugError(Exception):
    """A failure the agent should read and act on."""


def bootstrap() -> bool:
    """Import lldb from a discovered LLVM install. Returns True on success.

    Discovery: PICARO_LLDB_HOME, else the LLVM root inferred from `lldb` on
    PATH (scoop's layout is <root>/bin/lldb.exe + <root>/lib/site-packages).
    """
    global LLDB, LLDB_ERROR
    if LLDB is not None:
        return True
    if LLDB_ERROR:
        return False
    candidates = []
    override = os.environ.get("PICARO_LLDB_HOME")
    if override:
        candidates.append(Path(override))
    found = shutil.which("lldb.exe") or shutil.which("lldb")
    if found:
        resolved = Path(found).resolve()
        candidates.append(
            resolved.parent.parent if resolved.parent.name == "bin" else resolved.parent
        )
    for root in candidates:
        dll_dir = root / "bin"
        site_packages = root / "lib" / "site-packages"
        if not (dll_dir / "lldb.exe").is_file() or not (site_packages / "lldb").is_dir():
            continue
        try:
            os.add_dll_directory(str(dll_dir))
            sys.path.insert(0, str(site_packages))
            import lldb as lldb_module  # noqa: PLC0415 - by design, after path setup
        except Exception as exc:  # noqa: BLE001 - report, do not die
            LLDB_ERROR = f"importing lldb from {root} failed: {exc!r}"
            continue
        lldb_module.SBDebugger.Initialize()
        LLDB = lldb_module
        return True
    LLDB_ERROR = (
        "lldb with Python bindings not found; set PICARO_LLDB_HOME to an LLVM "
        "install (bin/lldb.exe + lib/site-packages/lldb) or put lldb on PATH"
    )
    return False


def version_string() -> str:
    if LLDB is None:
        return LLDB_ERROR or "lldb not bootstrapped"
    return LLDB.SBDebugger.GetVersionString().splitlines()[0]


def _lookup(constants: list, code: int, fallback: str) -> str:
    """Map an enum value to a name, tolerating constants this binding lacks."""
    for attribute, label in constants:
        value = getattr(LLDB, attribute, None)
        if value is not None and code == value:
            return label
    return f"{fallback}({code})"


def _file_spec_path(file_spec) -> str:
    """Full path of an SBFileSpec.

    This binding exposes the C-style GetPath(dst_path) (a buffer size that is
    unused, it returns the string), not the classic 0-arg overload.
    """
    try:
        return file_spec.GetPath(1024)
    except TypeError:
        return file_spec.GetPath()


def _state_name(state: int) -> str:
    return _lookup(
        [
            ("eStateInvalid", "invalid"),
            ("eStateUnloaded", "unloaded"),
            ("eStateAttached", "attached"),
            ("eStateDetached", "detached"),
            ("eStateExited", "exited"),
            ("eStateLaunching", "launching"),
            ("eStateStopped", "stopped"),
            ("eStateRunning", "running"),
            ("eStateStepping", "stepping"),
            ("eStateCrashed", "crashed"),
            ("eStateSuspended", "suspended"),
        ],
        state,
        "state",
    )


def _reason_name(reason: int) -> str:
    return _lookup(
        [
            ("eStopReasonInvalid", "invalid"),
            ("eStopReasonNone", "none"),
            ("eStopReasonTrace", "trace"),
            ("eStopReasonBreakpoint", "breakpoint"),
            ("eStopReasonWatchpoint", "watchpoint"),
            ("eStopReasonSignal", "signal"),
            ("eStopReasonException", "exception"),
            ("eStopReasonExec", "exec"),
            ("eStopReasonPlanComplete", "step-complete"),
            ("eStopReasonThreadExiting", "thread-exiting"),
            ("eStopReasonInstrumentation", "instrumentation"),
        ],
        reason,
        "reason",
    )


def describe_stop(info: dict) -> str:
    """One activity-log line for a stop result (`stop kind=breakpoint pc=... fn`)."""
    parts = [f"stop kind={info.get('kind', '?')}"]
    if info.get("pid") is not None:
        parts.append(f"pid={info['pid']}")
    frame = info.get("frame") or {}
    if frame:
        where = frame.get("function") or "?"
        location = f" ({frame['file']}:{frame['line']})" if frame.get("file") else ""
        parts.append(f"pc={frame.get('pc')} {where}{location}")
    if info.get("exit_status") is not None:
        parts.append(f"exit_status={info['exit_status']}")
    reason = (info.get("thread") or {}).get("reason")
    if reason and info.get("kind") in ("signal", "exception", "crashed"):
        parts.append(f"reason={reason}")
    return " ".join(parts)


class Session:
    """One target at a time, synchronous, watchdog-timed."""

    def __init__(self, on_event=None) -> None:
        # `on_event(line)` is called with a one-line description of everything
        # the session does; never let it break a session (see `_emit`).
        self.on_event = on_event
        self.debugger = LLDB.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.interpreter = self.debugger.GetCommandInterpreter()
        # Intel syntax for x86 disassembly; the CLI output is returned verbatim.
        self._run_command("settings set target.x86-disassembly-flavor intel")
        self.target = None
        self.process = None
        self.path = None
        self.out_path = None
        self.err_path = None
        self.bp_specs: dict[int, str] = {}

    # -- helpers ------------------------------------------------------------

    def _run_command(self, command: str) -> tuple[bool, str]:
        result = LLDB.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)
        text = (result.GetOutput() or "") + (result.GetError() or "")
        return result.Succeeded(), text

    def _emit(self, message: str) -> None:
        """Report one line of activity; a logging failure is never a session failure."""
        if self.on_event is None:
            return
        try:
            self.on_event(message)
        except Exception:  # noqa: BLE001 - the log is never worth a broken session
            pass

    def has_session(self) -> bool:
        return self.target is not None

    def require_stopped(self) -> None:
        if self.process is None:
            raise DebugError("no process in the session; launch or attach first")
        state = self.process.GetState()
        if state != LLDB.eStateStopped:
            raise DebugError(
                f"the process is not stopped (state: {_state_name(state)}); "
                "use debug_status / debug_close"
            )

    def ensure_thread(self):
        process = self.process
        thread = process.GetSelectedThread()
        if thread and thread.IsValid() and thread.GetThreadID() != 0:
            return thread
        for index in range(process.GetNumThreads()):
            candidate = process.GetThreadAtIndex(index)
            if candidate.GetStopReason() not in (
                LLDB.eStopReasonInvalid,
                LLDB.eStopReasonNone,
            ):
                process.SetSelectedThread(candidate)
                return candidate
        if process.GetNumThreads():
            candidate = process.GetThreadAtIndex(0)
            process.SetSelectedThread(candidate)
            return candidate
        raise DebugError("no threads available")

    def guarded(self, call, timeout_s: float) -> bool:
        """Run a blocking lldb call with a SendAsyncInterrupt watchdog.

        Returns True when the watchdog fired (the call hit its deadline).
        """
        process = self.process
        fired = {"value": False}

        def trip() -> None:
            fired["value"] = True
            try:
                process.SendAsyncInterrupt()
            except Exception:  # noqa: BLE001 - a dead process at the deadline
                pass

        timer = threading.Timer(max(0.5, timeout_s), trip)
        timer.start()
        try:
            call()
        finally:
            timer.cancel()
        return fired["value"]

    def output_tail(self, limit: int = 4000) -> dict:
        tails = {}
        for name, path in (("stdout", self.out_path), ("stderr", self.err_path)):
            if not path:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            text = text[-(limit):]
            if text.strip():
                tails[name] = text
        return tails

    def stop_info(
        self, *, fired: bool = False, expect_entry: bool = False, emit: bool = False
    ) -> dict:
        process = self.process
        state = process.GetState()
        info: dict = {
            "pid": process.GetProcessID(),
            "stop_id": process.GetStopID(),
            "state": _state_name(state),
        }
        if state == LLDB.eStateStopped:
            thread = self.ensure_thread()
            reason = thread.GetStopReason()
            reason_name = _reason_name(reason)
            if fired:
                kind = "timeout"
            elif reason == LLDB.eStopReasonBreakpoint:
                kind = "breakpoint"
            elif reason == LLDB.eStopReasonPlanComplete:
                kind = "step"
            elif reason == LLDB.eStopReasonException:
                kind = "exception"
            elif reason == LLDB.eStopReasonSignal and expect_entry:
                kind = "entry"
            elif reason == LLDB.eStopReasonSignal:
                kind = "signal"
            elif reason == LLDB.eStopReasonWatchpoint:
                kind = "watchpoint"
            else:
                kind = "stop"
            frame = thread.GetFrameAtIndex(0)
            line_entry = frame.GetLineEntry()
            info["kind"] = kind
            info["thread"] = {
                "id": thread.GetThreadID(),
                "reason": reason_name,
                "description": thread.GetStopDescription(200),
            }
            if reason == LLDB.eStopReasonBreakpoint:
                info["thread"]["breakpoint_id"] = thread.GetStopReasonDataAtIndex(0)
            if reason == LLDB.eStopReasonException:
                info["thread"]["reason_data"] = [
                    thread.GetStopReasonDataAtIndex(i) for i in range(2)
                ]
            info["frame"] = {
                "pc": hex(frame.GetPC()),
                "function": frame.GetFunctionName(),
                "file": line_entry.GetFileSpec().GetFilename(),
                "line": line_entry.GetLine(),
            }
        elif state == LLDB.eStateExited:
            info["kind"] = "exited"
            info["exit_status"] = process.GetExitStatus()
            info["exit_description"] = process.GetExitDescription()
        elif state == LLDB.eStateCrashed:
            info["kind"] = "crashed"
            info["exit_status"] = process.GetExitStatus()
            info["exit_description"] = process.GetExitDescription()
        elif state == LLDB.eStateDetached:
            info["kind"] = "detached"
        else:
            info["kind"] = _state_name(state)
        tails = self.output_tail()
        if tails:
            info["output"] = tails
        if emit:
            # Only the calls that move the target report a stop: a debug_status
            # poll returns the same info and must not fill the log with it.
            self._emit(describe_stop(info))
        return info

    # -- lifecycle ----------------------------------------------------------

    def launch(
        self,
        path: Path,
        args: list,
        cwd: Path | None,
        stop_at_entry: bool,
    ) -> dict:
        if self.has_session():
            raise DebugError("a session is already active; call debug_close first")
        error = LLDB.SBError()
        target = self.debugger.CreateTarget(str(path), None, None, True, error)
        if not target.IsValid():
            raise DebugError(f"cannot create a target for {path}: {error.GetCString()}")
        token = uuid.uuid4().hex[:8]
        self.out_path = os.path.join(tempfile.gettempdir(), f"picaro-mcp-{token}.out")
        self.err_path = os.path.join(tempfile.gettempdir(), f"picaro-mcp-{token}.err")
        launch_info = LLDB.SBLaunchInfo([str(part) for part in args])  # no argv[0]!
        if cwd:
            launch_info.SetWorkingDirectory(str(cwd))
        launch_info.AddOpenFileAction(0, "NUL", True, False)
        launch_info.AddOpenFileAction(1, self.out_path, False, True)
        launch_info.AddOpenFileAction(2, self.err_path, False, True)
        if stop_at_entry:
            launch_info.SetLaunchFlags(
                launch_info.GetLaunchFlags() | LLDB.eLaunchFlagStopAtEntry
            )
        self.target = target
        self.path = str(path)
        process = target.Launch(launch_info, error)
        if not process.IsValid():
            state = _state_name(process.GetState())
            self.discard()
            raise DebugError(f"launch failed ({state}): {error.GetCString()}")
        self.process = process
        self._emit(f"launch {Path(path).name} pid={process.GetProcessID()}")
        return self.stop_info(expect_entry=True, emit=True)

    def attach(self, *, pid: int | None, name: str | None) -> dict:
        if self.has_session():
            raise DebugError("a session is already active; call debug_close first")
        error = LLDB.SBError()
        target = self.debugger.CreateTarget(None, None, None, False, error)
        if not target.IsValid():
            raise DebugError(f"cannot create an attach target: {error.GetCString()}")
        listener = LLDB.SBListener("picaro-attach")
        if pid is not None:
            process = target.AttachToProcessWithID(listener, int(pid), error)
        elif name:
            process = target.AttachToProcessWithName(listener, str(name), False, error)
        else:
            raise DebugError("attach needs a pid or a name")
        if not process.IsValid() or not error.Success():
            raise DebugError(f"attach failed: {error.GetCString()}")
        self.target = target
        self.process = process
        self.path = f"attach:{pid or name}"
        self._emit(f"attach pid={process.GetProcessID()}")
        return self.stop_info(emit=True)

    def close(self, *, kill: bool = True) -> dict:
        if not self.has_session():
            return {"session": None, "note": "there was no active session"}
        info: dict = {"path": self.path, "pid": None}
        try:
            if self.process is not None:
                info["pid"] = self.process.GetProcessID()
                state = self.process.GetState()
                if state == LLDB.eStateStopped:
                    if kill:
                        self.process.Kill()
                        info["killed"] = True
                    else:
                        self.process.Detach()
                        info["detached"] = True
                info["final_state"] = _state_name(self.process.GetState())
            info["output"] = self.output_tail() or None
        finally:
            self.discard()
        info["session"] = None
        if info.get("killed"):
            action = "killed"
        elif info.get("detached"):
            action = "detached"
        else:
            action = "already-finished"  # exited or crashed before the close
        self._emit(
            f"close pid={info.get('pid')} {action} final_state={info.get('final_state')}"
        )
        return info

    def discard(self) -> None:
        """Drop the target without touching the process (already gone)."""
        target, self.target = self.target, None
        self.process = None
        self.bp_specs = {}
        if target is not None:
            try:
                self.debugger.DeleteTarget(target)
            except Exception:  # noqa: BLE001 - best effort
                pass

    def kill_on_shutdown(self) -> None:
        try:
            if self.process is not None:
                if self.process.GetState() == LLDB.eStateStopped:
                    self.process.Kill()
            self.discard()
        except Exception:  # noqa: BLE001 - shutting down
            pass

    # -- breakpoints --------------------------------------------------------

    def _main_module_base(self) -> int:
        executable = _file_spec_path(self.target.GetExecutable())
        for index in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(index)
            if _file_spec_path(module.GetFileSpec()) == executable:
                return module.GetObjectFileHeaderAddress().GetLoadAddress(self.target)
        raise DebugError("cannot locate the main module")

    def find_module(self, name: str) -> dict | None:
        """Loaded module whose filename matches `name` (with or without .dll)."""
        if self.target is None:
            return None
        needle = name.lower()
        variants = {needle}
        if "." not in needle:
            variants.add(needle + ".dll")
        for index in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(index)
            file_name = (module.GetFileSpec().GetFilename() or "").lower()
            if file_name in variants:
                base = module.GetObjectFileHeaderAddress().GetLoadAddress(self.target)
                return {
                    "name": module.GetFileSpec().GetFilename(),
                    "base": None if base == 0xFFFFFFFFFFFFFFFF else base,
                    "path": _file_spec_path(module.GetFileSpec()),
                }
        return None

    def _location_info(self, location) -> dict:
        address_value = location.GetAddress().GetLoadAddress(self.target)
        entry: dict = {
            "address": hex(address_value)
            if address_value != 0xFFFFFFFFFFFFFFFF
            else "pending"
        }
        try:
            function = location.GetAddress().GetFunction()
            if function and function.IsValid():
                entry["symbol"] = function.GetName()
            else:
                symbol = location.GetAddress().GetSymbol()
                if symbol and symbol.IsValid():
                    entry["symbol"] = symbol.GetName()
        except Exception:  # noqa: BLE001 - symbolization is best effort
            pass
        return entry

    def breakpoint_add(
        self, spec: str, *, hardware: bool = False, condition: str | None = None
    ) -> dict:
        if self.target is None:
            raise DebugError("no session; launch or attach first")
        before = self.target.GetNumBreakpoints()
        command_used = None
        if hardware:
            if spec.startswith("@") or spec.startswith("0x") or spec.startswith("+"):
                address = self.resolve_address(spec[1:] if spec.startswith("@") else spec)
                command_used = f"breakpoint set -H -a {hex(address)}"
            else:
                command_used = f'breakpoint set -H -n "{spec}"'
            ok, text = self._run_command(command_used)
            if not ok:
                raise DebugError(f"hardware breakpoint failed: {text.strip()}")
            if self.target.GetNumBreakpoints() <= before:
                raise DebugError(f"hardware breakpoint did not appear: {text.strip()}")
            bp = self.target.GetBreakpointAtIndex(self.target.GetNumBreakpoints() - 1)
        else:
            bp = self._software_breakpoint(spec)
        if condition:
            error = bp.SetCondition(condition)
            if not error.Success():
                raise DebugError(f"condition rejected: {error.GetCString()}")
        self.bp_specs[bp.GetID()] = spec
        locations = [
            self._location_info(bp.GetLocationAtIndex(index))
            for index in range(bp.GetNumLocations())
        ]
        self._emit(
            f"breakpoint set id={bp.GetID()} spec={spec}"
            f"{' hardware' if hardware else ''}"
            f" {'pending' if not locations else str(len(locations)) + ' location(s)'}"
            + (f" if {condition}" if condition else "")
        )
        return {
            "id": bp.GetID(),
            "spec": spec,
            "hardware": hardware,
            "command": command_used,
            "locations": locations,
            "pending": len(locations) == 0,
        }

    def _software_breakpoint(self, spec: str):
        target = self.target
        import re as _re

        if spec.startswith("re:"):
            return target.BreakpointCreateByRegex(spec[3:])
        if "!" in spec and not spec.startswith("@"):
            module, symbol = spec.split("!", 1)
            return target.BreakpointCreateByName(symbol, module)
        if _re.match(r"^.+:\d+$", spec) and not spec.startswith("@"):
            file_name, line = spec.rsplit(":", 1)
            return target.BreakpointCreateByLocation(file_name, int(line))
        if spec.startswith("+"):
            return target.BreakpointCreateByAddress(
                self._main_module_base() + int(spec[1:], 0)
            )
        if spec.startswith("@"):
            return target.BreakpointCreateByAddress(int(spec[1:], 0))
        if _re.match(r"^0x[0-9a-fA-F]+$", spec):
            return target.BreakpointCreateByAddress(int(spec, 16))
        breakpoint = target.BreakpointCreateByName(spec)
        if breakpoint.GetNumLocations() == 0:
            regex = target.BreakpointCreateByRegex(spec)
            if regex.GetNumLocations() > 0:
                target.BreakpointDelete(breakpoint.GetID())
                return regex
        return breakpoint

    def breakpoint_list(self) -> list:
        if self.target is None:
            raise DebugError("no session; launch or attach first")
        entries = []
        for index in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(index)
            locations = [
                self._location_info(bp.GetLocationAtIndex(loc_index))
                for loc_index in range(bp.GetNumLocations())
            ]
            entries.append(
                {
                    "id": bp.GetID(),
                    "spec": self.bp_specs.get(bp.GetID(), ""),
                    "enabled": bp.IsEnabled(),
                    "hardware": bp.IsHardware(),
                    "hit_count": bp.GetHitCount(),
                    "locations": locations,
                }
            )
        return entries

    def breakpoint_delete(self, bp_id: int) -> dict:
        if self.target is None:
            raise DebugError("no session; launch or attach first")
        ok = self.target.BreakpointDelete(int(bp_id))
        self.bp_specs.pop(int(bp_id), None)
        self._emit(f"breakpoint delete id={bp_id} deleted={bool(ok)}")
        return {"id": int(bp_id), "deleted": bool(ok)}

    def breakpoint_enable(self, bp_id: int, enabled: bool) -> dict:
        if self.target is None:
            raise DebugError("no session; launch or attach first")
        bp = self.target.FindBreakpointByID(int(bp_id))
        if not bp.IsValid():
            raise DebugError(f"no breakpoint with id {bp_id}")
        bp.SetEnabled(bool(enabled))
        self._emit(f"breakpoint enable id={bp_id} enabled={bool(bp.GetEnabled())}")
        return {"id": int(bp_id), "enabled": bool(bp.GetEnabled())}

    # -- execution ----------------------------------------------------------

    def continue_until_event(self, timeout_s: float) -> dict:
        self.require_stopped()
        self._emit(f"continue (timeout {timeout_s:g}s)")
        fired = self.guarded(self.process.Continue, timeout_s)
        return self.stop_info(fired=fired, emit=True)

    def step(self, kind: str, timeout_s: float) -> dict:
        self.require_stopped()
        thread = self.ensure_thread()
        if kind == "insn":
            call = lambda: thread.StepInstruction(True)  # noqa: E731
        elif kind == "into":
            call = lambda: thread.StepInto(True)  # noqa: E731
        elif kind == "over":
            call = lambda: thread.StepOver(True)  # noqa: E731
        elif kind == "out":
            call = lambda: thread.StepOut()  # noqa: E731
        else:
            raise DebugError(f"unknown step kind: {kind!r}")
        fired = self.guarded(call, timeout_s)
        return self.stop_info(fired=fired, emit=True)

    # -- inspection ---------------------------------------------------------

    def resolve_address(self, value) -> int:
        if isinstance(value, int):
            return value
        text = str(value).strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
        if self.process is not None and self.process.GetState() == LLDB.eStateStopped:
            frame = self.ensure_thread().GetFrameAtIndex(0)
            register = frame.FindRegister(text)
            if register and register.IsValid():
                return register.GetValueAsUnsigned()
        raise DebugError(f"cannot resolve address {value!r} (hex, decimal or register name)")

    def registers(self, thread_id: int | None, names: list | None) -> dict:
        self.require_stopped()
        if thread_id is not None:
            thread = self.process.GetThreadByID(int(thread_id))
            if not thread.IsValid():
                raise DebugError(f"no thread with id {thread_id}")
        else:
            thread = self.ensure_thread()
        frame = thread.GetFrameAtIndex(0)
        wanted = {name.lower() for name in names} if names else None
        out = {}
        for register_set in frame.GetRegisters():
            for register in register_set:
                name = register.GetName()
                if wanted is not None and name.lower() not in wanted:
                    continue
                out[name] = register.GetValue()
        return {"thread": thread.GetThreadID(), "registers": out}

    def read_memory(self, address, size: int) -> dict:
        self.require_stopped()
        size = max(1, min(int(size), 65536))
        target_address = self.resolve_address(address)
        error = LLDB.SBError()
        data = self.process.ReadMemory(target_address, size, error)
        result = {"address": hex(target_address), "requested": size}
        if data:
            result["size"] = len(data)
            result["hex"] = " ".join(f"{byte:02x}" for byte in data)
            result["ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        else:
            result["size"] = 0
            result["error"] = error.GetCString() or "unreadable"
        return result

    def write_memory(self, address, hex_bytes: str) -> dict:
        self.require_stopped()
        cleaned = (
            hex_bytes.replace(" ", "")
            .replace(",", "")
            .replace("0x", "")
            .replace("\\x", "")
        )
        try:
            data = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise DebugError(f"not valid hex bytes: {exc}") from None
        target_address = self.resolve_address(address)
        error = LLDB.SBError()
        written = self.process.WriteMemory(target_address, data, error)
        if written != len(data):
            raise DebugError(
                f"wrote {written}/{len(data)} bytes: {error.GetCString() or 'partial write'}"
            )
        self._emit(
            f"memory write {hex(target_address)} {written} bytes: {hex_bytes.strip()}"
        )
        return {"address": hex(target_address), "written": written, "readback": self.read_memory(target_address, written)}

    def memory_scan(
        self,
        pattern: str,
        start=None,
        max_results: int = 32,
        budget_s: float = 5.0,
    ) -> dict:
        self.require_stopped()
        if pattern.startswith("hex:"):
            cleaned = pattern[4:].replace(" ", "").replace(",", "").replace("0x", "")
            needle = bytes.fromhex(cleaned)
        elif pattern.startswith("ascii:"):
            needle = pattern[6:].encode("utf-8", "replace")
        else:
            needle = pattern.encode("utf-8", "replace")
        if not needle:
            raise DebugError("empty pattern")
        regions = self.process.GetMemoryRegions()
        start_address = self.resolve_address(start) if start is not None else None
        deadline = time.monotonic() + max(1.0, budget_s)
        results = []
        scanned = 0
        chunk_size = 1 << 22
        for index in range(regions.GetSize()):
            if len(results) >= max_results or time.monotonic() > deadline:
                break
            region = LLDB.SBMemoryRegionInfo()
            regions.GetMemoryRegionAtIndex(index, region)
            if not region.IsReadable():
                continue
            base, end = region.GetRegionBase(), region.GetRegionEnd()
            if start_address is not None:
                if not (base <= start_address < end):
                    continue
                base = start_address
            cursor = base
            overlap = len(needle) - 1
            tail = b""
            while cursor < end and len(results) < max_results and time.monotonic() < deadline:
                size = min(chunk_size, end - cursor)
                error = LLDB.SBError()
                data = self.process.ReadMemory(cursor, size, error)
                if not data:
                    break
                scanned += len(data)
                haystack = tail + data
                offset = 0
                while True:
                    found = haystack.find(needle, offset)
                    if found < 0:
                        break
                    results.append(hex(cursor - len(tail) + found))
                    if len(results) >= max_results:
                        break
                    offset = found + 1
                tail = haystack[-(overlap):] if overlap > 0 else b""
                cursor += len(data)
        return {
            "pattern": pattern,
            "matches": results,
            "scanned_bytes": scanned,
            "truncated": len(results) >= max_results,
        }

    def stack(self, thread_id: int | None, count: int) -> dict:
        self.require_stopped()
        if thread_id is not None:
            thread = self.process.GetThreadByID(int(thread_id))
        else:
            thread = self.ensure_thread()
        if not thread.IsValid():
            raise DebugError(f"no thread with id {thread_id}")
        frames = []
        for index in range(min(thread.GetNumFrames(), max(1, min(count, 200)))):
            frame = thread.GetFrameAtIndex(index)
            line = frame.GetLineEntry()
            functions = frame.GetFunctionName()
            frames.append(
                {
                    "index": index,
                    "pc": hex(frame.GetPC()),
                    "function": functions or None,
                    "file": line.GetFileSpec().GetFilename() or None,
                    "line": line.GetLine() if line.GetLine() != 0xFFFFFFFF else None,
                }
            )
        return {"thread": thread.GetThreadID(), "frames": frames}

    def threads(self) -> list:
        self.require_stopped()
        selected = 0
        thread = self.process.GetSelectedThread()
        if thread and thread.IsValid():
            selected = thread.GetThreadID()
        entries = []
        for index in range(self.process.GetNumThreads()):
            thread = self.process.GetThreadAtIndex(index)
            frame = thread.GetFrameAtIndex(0)
            entries.append(
                {
                    "id": thread.GetThreadID(),
                    "selected": thread.GetThreadID() == selected,
                    "stop_reason": _reason_name(thread.GetStopReason()),
                    "pc": hex(frame.GetPC()) if frame.IsValid() else None,
                }
            )
        return entries

    def select_thread(self, thread_id: int) -> dict:
        ok = self.process.SetSelectedThreadByID(int(thread_id))
        if not ok:
            raise DebugError(f"no thread with id {thread_id}")
        return {"selected": int(thread_id)}

    def modules(self, name_filter: str | None) -> list:
        if self.target is None:
            raise DebugError("no session; launch or attach first")
        entries = []
        needle = name_filter.lower() if name_filter else None
        for index in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(index)
            file_spec = module.GetFileSpec()
            name = file_spec.GetFilename()
            if needle and needle not in name.lower():
                continue
            base = module.GetObjectFileHeaderAddress().GetLoadAddress(self.target)
            entries.append(
                {
                    "name": name,
                    "path": _file_spec_path(file_spec),
                    "base": hex(base)
                    if base != 0xFFFFFFFFFFFFFFFF
                    else None,
                }
            )
        return entries

    def disassemble(self, address, count: int) -> str:
        self.require_stopped()
        if address is None:
            frame = self.ensure_thread().GetFrameAtIndex(0)
            target_address = frame.GetPC()
        else:
            target_address = self.resolve_address(address)
        count = max(1, min(int(count), 200))
        ok, text = self._run_command(
            f"disassemble --start-address {hex(target_address)} --count {count}"
        )
        if not ok and not text.strip():
            raise DebugError("disassembly failed")
        return text.strip()

    def evaluate(self, expression: str) -> dict:
        self.require_stopped()
        frame = self.ensure_thread().GetFrameAtIndex(0)
        value = frame.EvaluateExpression(expression)
        error = value.GetError()
        return {
            "expression": expression,
            "type": value.GetTypeName(),
            "value": value.GetValue(),
            "summary": value.GetSummary(),
            "error": error.GetCString() if error and not error.Success() else None,
        }

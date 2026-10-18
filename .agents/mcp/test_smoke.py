#!/usr/bin/env python3
"""Smoke test for the picaro-debugger MCP server (HTTP transport).

    python .agents/mcp/test_smoke.py            # analysis + debugger plumbing
    python .agents/mcp/test_smoke.py --quick    # analysis-only checks

The lab checks start a server with --lab and deliberately launch *benign*
targets under lldb: the repo's own picaro.exe (with --version) and a short
python sleeper. No packed artifact is ever run here. The debugger checks need
Defender real-time protection off, like any other lab run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
ROOT = HERE.parents[1]
PY = sys.executable


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    def __init__(self, *, lab: bool):
        self.port = free_port()
        cmd = [PY, str(SERVER), "--port", str(self.port)]
        if lab:
            cmd.append("--lab")
        # Capture the server's console to a *file*, never an undrained pipe: both
        # the server and the lldb-servers it spawns inherit this stdout, and a
        # ~4 KiB pipe nobody reads blocks whoever writes next -- the server before
        # it answers a request, or lldb-server before its handshake completes
        # (measured: `activity_log` hangs and `debug_attach` times out).
        self.log_path = Path(tempfile.gettempdir()) / f"picaro-smoke-{self.port}.log"
        self.log_file = self.log_path.open("w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._next_id = 0
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError("server exited early:\n" + self.output())
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/", timeout=2
                ) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.2)
        raise AssertionError("server did not become ready:\n" + self.output())

    def rpc(self, method: str, params=None, *, notify: bool = False):
        body: dict = {"jsonrpc": "2.0", "method": method}
        if not notify:
            self._next_id += 1
            body["id"] = self._next_id
        if params is not None:
            body["params"] = params
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mcp",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=180) as response:
            if notify:
                return response.status, None
            raw = response.read()
            try:
                return response.status, json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                raise AssertionError(
                    f"bad response body ({len(raw)} bytes): {raw[:200]!r}"
                ) from None

    def initialize(self) -> None:
        _, message = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "picaro-debugger-smoke", "version": "0"},
            },
        )
        assert message["result"]["serverInfo"]["name"] == "picaro-debugger", message

    def tools(self) -> list:
        _, message = self.rpc("tools/list")
        return [tool["name"] for tool in message["result"]["tools"]]

    def tool(self, name: str, arguments: dict) -> dict:
        _, message = self.rpc("tools/call", {"name": name, "arguments": arguments})
        assert "result" in message, message
        return message["result"]

    def get(self, path: str) -> tuple:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}{path}", timeout=10
        ) as response:
            return response.status, response.read().decode("utf-8", "replace")

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        try:
            self.log_file.close()
        except Exception:
            pass

    def output(self) -> str:
        try:
            self.log_file.flush()
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""


def text_of(result: dict) -> str:
    return result["content"][0]["text"]


def is_error(result: dict) -> bool:
    return bool(result.get("isError"))


def run_checks(server: Server, function) -> None:
    """Run a check; on failure include the server's log for diagnosis."""
    try:
        function(server)
    except Exception as exc:
        server.stop()
        raise AssertionError(
            f"{exc!r}\n--- server log ---\n{server.output()[-4000:]}"
        ) from None
    else:
        server.stop()


def check_analysis() -> None:
    run_checks(Server(lab=False), analysis_checks)


def analysis_checks(server: Server) -> None:
    server.initialize()
    names = server.tools()
    for expected in (
        "audit_file",
        "hash_file",
        "pe_info",
        "export_lookup",
        "disassemble_file",
        "strings_file",
        "yara_scan",
        "techniques_list",
        "technique_show",
        "techniques_validate",
        "build_plan",
        "defender_status",
        "activity_log",
    ):
        assert expected in names, names
    for absent in ("run_artifact", "debug_launch", "bp_set"):
        assert absent not in names, names

    status, _ = server.rpc("notifications/initialized", notify=True)
    assert status == 202, status

    result = server.tool("run_artifact", {"path": "dist/whatever.exe"})
    assert is_error(result) and "--lab" in text_of(result), result

    # The activity log records the refusal, the call and the result of every tool.
    result = server.tool("activity_log", {"kind": "error"})
    events = json.loads(text_of(result))["events"]
    assert any("run_artifact" in event["text"] for event in events), events

    fixture = ROOT / "tests" / "fixtures" / "minimal_x86.exe"
    result = server.tool("hash_file", {"path": "tests/fixtures/minimal_x86.exe"})
    assert (
        json.loads(text_of(result))["sha256"]
        == hashlib.sha256(fixture.read_bytes()).hexdigest()
    )

    result = server.tool("activity_log", {"kind": "tool", "limit": 10})
    logged = json.loads(text_of(result))
    texts = [event["text"] for event in logged["events"]]
    assert any(text.startswith("-> hash_file") for text in texts), texts
    assert any(text.startswith("<- hash_file ok") for text in texts), texts
    assert logged["log_file"] and Path(logged["log_file"]).is_file(), logged["log_file"]

    last_seq = logged["events"][-1]["seq"]
    result = server.tool("activity_log", {"since": last_seq})
    newer = json.loads(text_of(result))["events"]
    assert all(event["seq"] > last_seq for event in newer), newer
    # Only the call just made can be newer than the snapshot.
    assert all("activity_log" in event["text"] for event in newer), newer

    status, body = server.get("/log?tail=20")
    assert status == 200 and "-> hash_file" in body, body

    status, body = server.get("/status")
    assert status == 200 and "picaro-debugger" in body, body

    result = server.tool("pe_info", {"path": "examples/payloads/test_payload.exe"})
    info = json.loads(text_of(result))
    assert info["machine"] in ("x64", "x86"), info
    assert info["entry_point_va"].startswith("0x"), info

    result = server.tool("export_lookup", {"module": "ntdll", "name": "NtAllocateVirtualMemory"})
    export = json.loads(text_of(result))
    assert export["rva"].startswith("0x"), export

    result = server.tool(
        "disassemble_file",
        {"path": "tests/fixtures/minimal_x64.exe", "at": "+0x1000", "count": 4},
    )
    disasm = json.loads(text_of(result))
    assert disasm["instructions"], disasm

    result = server.tool("strings_file", {"path": "tests/fixtures/minimal_x64.exe"})
    strings = json.loads(text_of(result))
    assert "raw_count" in strings and "strings" in strings, strings

    result = server.tool("yara_scan", {"path": "tests/fixtures/minimal_x64.exe"})
    if is_error(result):
        assert "yara" in text_of(result).lower(), result
    else:
        assert "matches" in json.loads(text_of(result)), result

    # Project inspection: the technique registry, read without touching picaro.
    result = server.tool("techniques_list", {})
    assert "reflective_loading" in text_of(result), text_of(result)

    result = server.tool("technique_show", {"name": "reflective_loading"})
    assert "Reflective loading" in text_of(result), text_of(result)[:200]

    result = server.tool("technique_show", {"name": "no-such-technique"})
    assert is_error(result), result

    result = server.tool("techniques_validate", {})
    assert "OK" in text_of(result), text_of(result)

    result = server.tool("audit_file", {"path": "tests/fixtures/minimal_x86.exe"})
    assert json.loads(text_of(result))["report_schema"] == 1

    # `--json` ignores `--focus`, so the tool trims the report itself.
    result = server.tool(
        "audit_file", {"path": "tests/fixtures/minimal_x86.exe", "focus": "imports"}
    )
    focused = json.loads(text_of(result))
    assert focused["report_schema"] == 1, focused
    assert "imports" in focused and "strings" not in focused, focused

    # A named build lands on a stable path and the tool reports it back.
    result = server.tool(
        "build_plan",
        {"plan": "examples/plans/reflective-loading.yaml", "debug": True, "name": "smoke-dbg"},
    )
    built = json.loads(text_of(result))
    assert built["build_name"] == "smoke-dbg", built
    assert built["stub_exe"].endswith(str(Path("build") / "smoke-dbg" / "out.exe")), built
    assert Path(built["stub_exe"]).is_file(), built
    assert Path(built["stub_source"]).is_file(), built


def check_lab() -> None:
    run_checks(Server(lab=True), lab_checks)


def lab_checks(server: Server) -> None:
    server.initialize()
    names = server.tools()
    for expected in (
        "run_artifact",
        "debug_launch",
        "debug_attach",
        "bp_set",
        "run_until_event",
        "step",
        "registers",
        "read_memory",
        "memory_scan",
    ):
        assert expected in names, names

    result = server.tool("debug_launch", {"path": "build/definitely-missing.exe"})
    assert is_error(result) and "no such executable" in text_of(result), result

    # --- plumbing run: the repo's own binary under lldb ---
    result = server.tool(
        "debug_launch",
        {
            "path": "target/debug/picaro.exe",
            "args": ["--version"],
            "stop_at_entry": True,
        },
    )
    assert not is_error(result), result
    stop = json.loads(text_of(result))
    assert stop["state"] == "stopped", stop
    assert stop["kind"] in ("entry", "signal"), stop
    assert isinstance(stop["pid"], int) and stop["pid"] > 0, stop

    result = server.tool("bp_set", {"spec": "picaro::main"})
    breakpoint = json.loads(text_of(result))
    assert breakpoint["locations"], breakpoint

    result = server.tool("run_until_event", {"timeout_s": 20})
    stop = json.loads(text_of(result))
    assert stop["kind"] == "breakpoint", stop
    assert "picaro::main" in (stop["frame"]["function"] or ""), stop

    result = server.tool("registers", {"names": ["rip", "rsp"]})
    registers = json.loads(text_of(result))["registers"]
    assert registers["rip"].startswith("0x"), registers

    result = server.tool("read_memory", {"address": "rip", "size": 16})
    memory = json.loads(text_of(result))
    assert memory["size"] == 16 and memory["hex"], memory

    result = server.tool("stack", {"count": 5})
    assert json.loads(text_of(result))["frames"], result

    result = server.tool("modules", {"filter": "picaro"})
    modules = json.loads(text_of(result))["modules"]
    assert any("picaro.exe" in module["name"] for module in modules), modules

    result = server.tool("step", {"kind": "insn", "timeout_s": 10})
    stop = json.loads(text_of(result))
    assert stop["kind"] in ("step",), stop

    result = server.tool("run_until_event", {"timeout_s": 15})
    stop = json.loads(text_of(result))
    assert stop["kind"] == "exited" and stop["exit_status"] == 0, stop
    assert "picaro" in json.dumps(stop.get("output", {})).lower(), stop

    result = server.tool("debug_status", {})
    assert json.loads(text_of(result))["state"] == "exited", result

    # The debugger reports its own events: launch, breakpoint, stop, exit.
    result = server.tool("activity_log", {"kind": "debug", "limit": 100})
    debug_events = [event["text"] for event in json.loads(text_of(result))["events"]]
    joined = "\n".join(debug_events)
    assert "launch picaro.exe" in joined, joined
    assert "breakpoint set" in joined, joined
    assert "stop kind=exited" in joined, joined

    server.tool("debug_close", {})

    # --- watchdog path: a 5s sleeper interrupted at 1s ---
    result = server.tool(
        "debug_launch",
        {"path": PY, "args": ["-c", "import time; time.sleep(5)"]},
    )
    assert not is_error(result), result
    started = time.time()
    result = server.tool("run_until_event", {"timeout_s": 1})
    elapsed = time.time() - started
    stop = json.loads(text_of(result))
    assert stop["kind"] == "timeout", stop
    assert elapsed < 4, f"watchdog too slow: {elapsed:.2f}s"
    server.tool("debug_close", {"kill": True})

    # --- live output: the ticker mirrors what the target prints while it runs ---
    printer = "import time\nfor i in range(6):\n    print('tick', i, flush=True)\n    time.sleep(0.5)"
    result = server.tool("debug_launch", {"path": PY, "args": ["-c", printer]})
    assert not is_error(result), result
    running = server.tool("run_until_event", {"timeout_s": 2})
    assert json.loads(text_of(running))["kind"] == "timeout", running
    result = server.tool("activity_log", {"kind": "target", "limit": 20})
    printed = [event["text"] for event in json.loads(text_of(result))["events"]]
    assert any("tick" in text for text in printed), printed
    server.tool("debug_close", {"kill": True})

    # --- attach to a live sleeper ---
    sleeper = subprocess.Popen([PY, "-c", "import time; time.sleep(30)"])
    try:
        result = server.tool("debug_attach", {"pid": sleeper.pid})
        assert not is_error(result), result
        stop = json.loads(text_of(result))
        assert stop["pid"] == sleeper.pid, stop
        server.tool("debug_close", {"kill": False})
    finally:
        sleeper.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="picaro-debugger MCP smoke test")
    parser.add_argument(
        "--quick", action="store_true", help="analysis-only checks, no debugger"
    )
    options = parser.parse_args()

    checks = [("analysis-only mode", check_analysis)]
    if not options.quick:
        checks.append(("lab mode + debugger plumbing", check_lab))

    failures = 0
    for name, function in checks:
        try:
            function()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures += 1
            print(f"FAIL {name}: {exc!r}")
        else:
            print(f"ok   {name}")
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

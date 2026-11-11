"""argv templates + the sandboxed subprocess engine that actually runs nmap.

Nothing here ever accepts a raw flag from a caller. Each ``build_*_argv``
function takes already-validated, scalar parameters and returns a fixed
argv shape; :class:`NmapRunner` is the only thing that invokes nmap, always
via ``create_subprocess_exec`` (never a shell), always with ``-oX -``, and
always under a hard timeout with a semaphore limiting concurrency.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Sequence

from .config import Config
from .models import ScanResult
from .parser import ParserError, parse_nmap_xml

PORT_SPEC_RE = re.compile(
    r"^(?:[TU]:)?\d{1,5}(?:-\d{1,5})?(?:,(?:[TU]:)?\d{1,5}(?:-\d{1,5})?)*$"
)

SCAN_TYPE_FLAGS = {"syn": "-sS", "connect": "-sT", "udp": "-sU"}

#: Flags/options the AI must never be able to cause us to emit. Checked as a
#: defense-in-depth assertion over every argv this module builds.
FORBIDDEN_TOKENS = {
    "-oN", "-oG", "-oA", "--script-args-file", "--datadir", "--resume",
    "-iL", "--excludefile", "-D", "-S", "-e", "--spoof-mac", "--proxies",
    "-b", "-sI", "-f", "--mtu", "--badsum", "--data-length", "-T5", "-T6",
}

#: Hardcoded script sets for the protocol-audit tools (Phase 2). Verified
#: against the installed nmap's script.db at startup; see scripts.py.
PROTOCOL_SCRIPTS: dict[str, tuple[list[str], list[str]]] = {
    "ssl_audit": (["ssl-cert", "ssl-enum-ciphers", "ssl-date"], []),
    "http_audit": (
        ["http-title", "http-headers", "http-server-header", "http-methods", "http-robots.txt"],
        ["http-security-headers"],
    ),
    "ssh_audit": (["ssh2-enum-algos", "ssh-hostkey"], []),
    "smb_audit": (["smb-os-discovery", "smb-protocols", "smb2-security-mode", "smb-security-mode"], []),
    "rdp_audit": (["rdp-enum-encryption", "rdp-ntlm-info"], []),
    "dns_audit": (["dns-recursion", "dns-nsid"], []),
    "database_audit": (["mysql-info", "ms-sql-info", "ms-sql-ntlm-info", "mongodb-info", "redis-info"], []),
}

#: Fixed default ports for protocol-audit tools that don't take a `ports` param.
PROTOCOL_DEFAULT_PORTS = {
    "smb_audit": "139,445",
    "rdp_audit": "3389",
    "dns_audit": "53",
    "database_audit": "1433,3306,6379,27017",
}


class RunnerError(ValueError):
    """A parameter failed validation before it could become part of argv."""


def validate_ports(ports: str) -> str:
    if ports == "":
        return ports
    if not PORT_SPEC_RE.match(ports):
        raise RunnerError(
            f"Invalid port spec {ports!r}; expected e.g. '80', '1-1024', 'T:80,U:53'."
        )
    for part in ports.split(","):
        token = part[2:] if part[:2] in ("T:", "U:") else part
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
        else:
            start = end = int(token)
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise RunnerError(f"Port out of range (1-65535) in {ports!r}.")
        if start > end:
            raise RunnerError(f"Port range start > end in {ports!r}.")
    return ports


def count_ports(ports: str) -> int:
    if not ports:
        return 0
    total = 0
    for part in ports.split(","):
        token = part[2:] if part[:2] in ("T:", "U:") else part
        if "-" in token:
            a, b = token.split("-", 1)
            total += int(b) - int(a) + 1
        else:
            total += 1
    return total


def timing_flag(cfg: Config, requested: int = 4) -> str:
    level = max(0, min(requested, cfg.max_timing))
    return f"-T{level}"


def assert_no_forbidden_flags(argv: Sequence[str]) -> None:
    present = FORBIDDEN_TOKENS & set(argv)
    if present:
        raise RunnerError(f"Built argv contains forbidden tokens: {sorted(present)!r}")


def _append_ports(argv: list[str], ports: str) -> None:
    if ports:
        argv += ["-p", validate_ports(ports)]


def _append_scripts(argv: list[str], scripts: Sequence[str], script_args: str | None = None) -> None:
    if scripts:
        argv += ["--script", ",".join(sorted(set(scripts)))]
        if script_args:
            argv += ["--script-args", script_args]


# --------------------------------------------------------------------------
# Phase 1: core tools
# --------------------------------------------------------------------------

def build_discover_argv(cfg: Config, targets: Sequence[str]) -> list[str]:
    return ["-sn", timing_flag(cfg), *targets]


def build_quick_scan_argv(cfg: Config, targets: Sequence[str], top_ports: int) -> list[str]:
    n = max(1, min(int(top_ports), 1000))
    return [timing_flag(cfg, requested=4), "--top-ports", str(n), *targets]


def build_port_scan_argv(
    cfg: Config, targets: Sequence[str], scan_type: str, ports: str
) -> list[str]:
    flag = SCAN_TYPE_FLAGS.get(scan_type)
    if flag is None:
        raise RunnerError(f"scan_type must be one of {sorted(SCAN_TYPE_FLAGS)}, got {scan_type!r}")

    argv = [flag, timing_flag(cfg)]
    if scan_type == "udp":
        if ports:
            validated = validate_ports(ports)
            if count_ports(validated) > 200:
                raise RunnerError("UDP scans are capped at 200 ports; narrow the port spec.")
            argv += ["-p", validated]
        else:
            argv += ["--top-ports", "200"]
    else:
        _append_ports(argv, ports)
    argv += list(targets)
    return argv


def build_service_scan_argv(
    cfg: Config, targets: Sequence[str], ports: str, intensity: int
) -> list[str]:
    level = max(0, min(int(intensity), 9))
    argv = ["-sV", timing_flag(cfg), "--version-intensity", str(level)]
    _append_ports(argv, ports)
    argv += list(targets)
    return argv


def build_os_detect_argv(cfg: Config, targets: Sequence[str]) -> list[str]:
    return ["-O", "--osscan-guess", timing_flag(cfg), *targets]


def build_script_scan_argv(
    cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str
) -> list[str]:
    argv = [timing_flag(cfg)]
    _append_ports(argv, ports)
    _append_scripts(argv, scripts)
    argv += list(targets)
    return argv


# --------------------------------------------------------------------------
# Phase 2: workflows and protocol audits
# --------------------------------------------------------------------------

def build_service_sweep_argv(cfg: Config, targets: Sequence[str], top_ports: int = 100) -> list[str]:
    """Second phase of network_inventory: -sV on hosts already known to be up."""

    n = max(1, min(int(top_ports), 1000))
    return ["-sV", timing_flag(cfg), "--top-ports", str(n), *targets]


def build_host_summary_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str]) -> list[str]:
    argv = ["-sV", "-O", "--osscan-guess", timing_flag(cfg)]
    _append_scripts(argv, scripts)
    argv += list(targets)
    return argv


def _build_protocol_audit_argv(
    cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str, *, udp: bool = False
) -> list[str]:
    argv = ["-sU" if udp else "-sS", timing_flag(cfg)]
    _append_ports(argv, ports)
    _append_scripts(argv, scripts)
    argv += list(targets)
    return argv


def build_ssl_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, ports)


def build_http_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, ports)


def build_ssh_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, ports)


def build_smb_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str]) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, PROTOCOL_DEFAULT_PORTS["smb_audit"])


def build_rdp_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str]) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, PROTOCOL_DEFAULT_PORTS["rdp_audit"])


def build_dns_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str]) -> list[str]:
    return _build_protocol_audit_argv(
        cfg, targets, scripts, PROTOCOL_DEFAULT_PORTS["dns_audit"], udp=True
    )


def build_database_audit_argv(cfg: Config, targets: Sequence[str], scripts: Sequence[str]) -> list[str]:
    return _build_protocol_audit_argv(cfg, targets, scripts, PROTOCOL_DEFAULT_PORTS["database_audit"])


def build_vuln_scan_argv(
    cfg: Config, targets: Sequence[str], scripts: Sequence[str], ports: str
) -> list[str]:
    argv = ["-sV", timing_flag(cfg)]
    _append_ports(argv, ports)
    _append_scripts(argv, scripts)
    argv += list(targets)
    return argv


# --------------------------------------------------------------------------
# Execution engine
# --------------------------------------------------------------------------

@dataclass
class ScanOutcome:
    argv: list[str]
    exit_code: int | None
    duration_seconds: float
    timed_out: bool
    raw_xml: str
    stderr_tail: str
    result: ScanResult = field(default_factory=ScanResult)
    parse_error: str | None = None


class NmapRunner:
    def __init__(self, cfg: Config, nmap_path: str = "nmap"):
        self.cfg = cfg
        self.nmap_path = nmap_path
        self._semaphore = asyncio.Semaphore(max(1, cfg.max_parallel))

    async def run(
        self,
        argv_tail: Sequence[str],
        *,
        tool: str,
        target_display: str,
        resolved_targets: Sequence[str],
    ) -> ScanOutcome:
        host_timeout = max(1, self.cfg.timeout)
        full_argv = [
            self.nmap_path,
            "-oX",
            "-",
            "--host-timeout",
            f"{host_timeout}s",
            *argv_tail,
        ]
        assert_no_forbidden_flags(full_argv)

        async with self._semaphore:
            start = time.monotonic()
            outcome = await self._exec(full_argv)
            duration = time.monotonic() - start

        result = ScanResult()
        parse_error = None
        if outcome["raw_stdout"].strip():
            try:
                result = parse_nmap_xml(outcome["raw_stdout"])
            except ParserError as exc:
                parse_error = str(exc)

        self._log(
            tool=tool,
            target_display=target_display,
            resolved_targets=resolved_targets,
            argv=full_argv,
            duration=duration,
            exit_code=outcome["exit_code"],
            timed_out=outcome["timed_out"],
        )

        return ScanOutcome(
            argv=full_argv,
            exit_code=outcome["exit_code"],
            duration_seconds=duration,
            timed_out=outcome["timed_out"],
            raw_xml=outcome["raw_stdout"],
            stderr_tail=outcome["raw_stderr"][-2000:],
            result=result,
            parse_error=parse_error,
        )

    async def _exec(self, argv: list[str]) -> dict:
        kwargs: dict = {}
        if os.name != "nt":
            kwargs["preexec_fn"] = os.setsid

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        async def _drain(stream: asyncio.StreamReader | None, sink: list[bytes]) -> None:
            if stream is None:
                return
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                sink.append(chunk)

        stdout_task = asyncio.create_task(_drain(proc.stdout, stdout_chunks))
        stderr_task = asyncio.create_task(_drain(proc.stderr, stderr_chunks))

        timed_out = False
        try:
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task, proc.wait()),
                timeout=self.cfg.timeout,
            )
        except asyncio.TimeoutError:
            timed_out = True
            await self._kill(proc)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        return {
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "raw_stdout": b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            "raw_stderr": b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        }

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        try:
            if os.name == "nt":
                killer = await asyncio.create_subprocess_exec(
                    "taskkill", "/T", "/F", "/PID", str(proc.pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
            else:
                os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, OSError):
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass

    @staticmethod
    def _log(
        *,
        tool: str,
        target_display: str,
        resolved_targets: Sequence[str],
        argv: Sequence[str],
        duration: float,
        exit_code: int | None,
        timed_out: bool,
    ) -> None:
        print(
            f"nmap-mcp scan: tool={tool} target={target_display!r} "
            f"resolved={list(resolved_targets)} argv={list(argv)} "
            f"duration={duration:.2f}s exit_code={exit_code} timed_out={timed_out}",
            file=sys.stderr,
        )

from __future__ import annotations

import asyncio
import sys

import pytest

from nmap_mcp.config import Config
from nmap_mcp.runner import (
    FORBIDDEN_TOKENS,
    NmapRunner,
    RunnerError,
    assert_no_forbidden_flags,
    build_database_audit_argv,
    build_discover_argv,
    build_dns_audit_argv,
    build_host_summary_argv,
    build_http_audit_argv,
    build_os_detect_argv,
    build_port_scan_argv,
    build_quick_scan_argv,
    build_rdp_audit_argv,
    build_script_scan_argv,
    build_service_scan_argv,
    build_service_sweep_argv,
    build_smb_audit_argv,
    build_ssh_audit_argv,
    build_ssl_audit_argv,
    build_vuln_scan_argv,
    count_ports,
    timing_flag,
    validate_ports,
)


def _cfg(**overrides) -> Config:
    base = dict(allowed_targets=("192.168.1.0/24",), max_timing=4, timeout=600, max_parallel=2)
    base.update(overrides)
    return Config(**base)


# ---- port validation ----------------------------------------------------

@pytest.mark.parametrize("ports", ["80", "1-1024", "T:80,U:53", "80,443,8080", "U:53"])
def test_valid_port_specs_pass(ports):
    assert validate_ports(ports) == ports


def test_empty_port_spec_is_a_noop():
    assert validate_ports("") == ""


@pytest.mark.parametrize(
    "ports",
    ["80;rm -rf", "0", "65536", "100-50", "80,", "abc", "80 443", "-p80", "80/tcp", "80--443"],
)
def test_invalid_port_specs_rejected(ports):
    with pytest.raises(RunnerError):
        validate_ports(ports)


def test_count_ports():
    assert count_ports("") == 0
    assert count_ports("80") == 1
    assert count_ports("1-100") == 100
    assert count_ports("80,443,U:53") == 3
    assert count_ports("1-10,20-29") == 20


# ---- timing --------------------------------------------------------------

def test_timing_never_exceeds_cfg_max():
    assert timing_flag(_cfg(max_timing=2), requested=4) == "-T2"


def test_timing_respects_lower_request():
    assert timing_flag(_cfg(max_timing=4), requested=1) == "-T1"


def test_timing_never_exceeds_absolute_ceiling_even_if_requested_high():
    assert timing_flag(_cfg(max_timing=4), requested=10) == "-T4"


# ---- argv builders: every tool, property-tested for forbidden flags -----

BUILDERS = [
    lambda cfg: build_discover_argv(cfg, ["192.168.1.10"]),
    lambda cfg: build_quick_scan_argv(cfg, ["192.168.1.10"], 5000),
    lambda cfg: build_port_scan_argv(cfg, ["192.168.1.10"], "syn", "1-100"),
    lambda cfg: build_port_scan_argv(cfg, ["192.168.1.10"], "connect", ""),
    lambda cfg: build_port_scan_argv(cfg, ["192.168.1.10"], "udp", ""),
    lambda cfg: build_service_scan_argv(cfg, ["192.168.1.10"], "", 99),
    lambda cfg: build_os_detect_argv(cfg, ["192.168.1.10"]),
    lambda cfg: build_script_scan_argv(cfg, ["192.168.1.10"], ["ssl-cert"], "443"),
    lambda cfg: build_service_sweep_argv(cfg, ["192.168.1.10"]),
    lambda cfg: build_host_summary_argv(cfg, ["192.168.1.10"], ["ssl-cert", "http-title"]),
    lambda cfg: build_ssl_audit_argv(cfg, ["192.168.1.10"], ["ssl-cert"], "443"),
    lambda cfg: build_http_audit_argv(cfg, ["192.168.1.10"], ["http-title"], "80,443"),
    lambda cfg: build_ssh_audit_argv(cfg, ["192.168.1.10"], ["ssh-hostkey"], "22"),
    lambda cfg: build_smb_audit_argv(cfg, ["192.168.1.10"], ["smb-os-discovery"]),
    lambda cfg: build_rdp_audit_argv(cfg, ["192.168.1.10"], ["rdp-ntlm-info"]),
    lambda cfg: build_dns_audit_argv(cfg, ["192.168.1.10"], ["dns-recursion"]),
    lambda cfg: build_database_audit_argv(cfg, ["192.168.1.10"], ["mysql-info"]),
    lambda cfg: build_vuln_scan_argv(cfg, ["192.168.1.10"], ["vulners"], ""),
]


@pytest.mark.parametrize("build", BUILDERS)
def test_no_builder_emits_forbidden_flags(build):
    argv = build(_cfg())
    present = FORBIDDEN_TOKENS & set(argv)
    assert not present, f"forbidden tokens in argv: {present} ({argv})"
    # The full argv (as NmapRunner.run would prepend) must also pass the assertion.
    assert_no_forbidden_flags(["nmap", "-oX", "-", "--host-timeout", "600s", *argv])


def test_quick_scan_caps_top_ports_at_1000():
    argv = build_quick_scan_argv(_cfg(), ["10.0.0.1"], 5000)
    assert argv[argv.index("--top-ports") + 1] == "1000"


def test_quick_scan_floors_top_ports_at_1():
    argv = build_quick_scan_argv(_cfg(), ["10.0.0.1"], -5)
    assert argv[argv.index("--top-ports") + 1] == "1"


def test_service_scan_clamps_intensity_0_to_9():
    argv = build_service_scan_argv(_cfg(), ["10.0.0.1"], "", 99)
    assert argv[argv.index("--version-intensity") + 1] == "9"
    argv = build_service_scan_argv(_cfg(), ["10.0.0.1"], "", -5)
    assert argv[argv.index("--version-intensity") + 1] == "0"


def test_port_scan_rejects_bad_scan_type():
    with pytest.raises(RunnerError):
        build_port_scan_argv(_cfg(), ["10.0.0.1"], "xmas", "")


def test_udp_port_scan_caps_at_200_ports():
    with pytest.raises(RunnerError, match="capped at 200"):
        build_port_scan_argv(_cfg(), ["10.0.0.1"], "udp", "1-500")


def test_udp_port_scan_defaults_to_top_200_without_explicit_ports():
    argv = build_port_scan_argv(_cfg(), ["10.0.0.1"], "udp", "")
    assert argv[argv.index("--top-ports") + 1] == "200"


def test_script_scan_never_passes_bare_category():
    argv = build_script_scan_argv(_cfg(), ["10.0.0.1"], ["ssl-cert", "ssl-date"], "")
    script_arg = argv[argv.index("--script") + 1]
    assert set(script_arg.split(",")) == {"ssl-cert", "ssl-date"}


# ---- execution engine -----------------------------------------------------

async def test_runner_executes_and_captures_stdout():
    cfg = _cfg(timeout=5, max_parallel=1)
    eng = NmapRunner(cfg, nmap_path=sys.executable)
    outcome = await eng._exec([sys.executable, "-c", "print('<nmaprun></nmaprun>')"])
    assert outcome["exit_code"] == 0
    assert "<nmaprun>" in outcome["raw_stdout"]
    assert outcome["timed_out"] is False


async def test_runner_timeout_kills_process_and_returns_partial_output():
    cfg = _cfg(timeout=1, max_parallel=1)
    eng = NmapRunner(cfg, nmap_path=sys.executable)
    script = "import sys, time; sys.stdout.write('PARTIAL-XML'); sys.stdout.flush(); time.sleep(30)"
    outcome = await eng._exec([sys.executable, "-c", script])
    assert outcome["timed_out"] is True
    assert "PARTIAL-XML" in outcome["raw_stdout"]


async def test_semaphore_limits_concurrency(monkeypatch):
    cfg = _cfg(max_parallel=1, timeout=5)
    eng = NmapRunner(cfg, nmap_path="nmap")

    active = 0
    max_active = 0

    async def fake_exec(argv):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.05)
        active -= 1
        return {"exit_code": 0, "timed_out": False, "raw_stdout": "", "raw_stderr": ""}

    monkeypatch.setattr(eng, "_exec", fake_exec)

    await asyncio.gather(
        eng.run(["-sn"], tool="t", target_display="d", resolved_targets=["10.0.0.1"]),
        eng.run(["-sn"], tool="t", target_display="d", resolved_targets=["10.0.0.1"]),
        eng.run(["-sn"], tool="t", target_display="d", resolved_targets=["10.0.0.1"]),
    )

    assert max_active == 1

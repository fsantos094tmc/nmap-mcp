"""Opt-in live test: needs a real nmap binary and loopback access.

Run with: uv run pytest -m live
"""

from __future__ import annotations

import shutil

import pytest

from nmap_mcp.config import Config
from nmap_mcp.runner import NmapRunner, build_quick_scan_argv
from nmap_mcp.scope import resolve_target

pytestmark = pytest.mark.live


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
async def test_quick_scan_localhost_returns_a_result():
    cfg = Config(allowed_targets=("127.0.0.1/32",), timeout=60, max_parallel=1)
    resolved = resolve_target("127.0.0.1", cfg)

    engine = NmapRunner(cfg)
    argv_tail = build_quick_scan_argv(cfg, resolved.nmap_targets, top_ports=20)
    outcome = await engine.run(
        argv_tail, tool="quick_scan", target_display=resolved.display, resolved_targets=resolved.nmap_targets
    )

    assert outcome.exit_code == 0
    assert outcome.result.run_stats.hosts_total >= 1

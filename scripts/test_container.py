#!/usr/bin/env python3
"""Smoke-test the built image: send `initialize` + `tools/list` over stdio
and check that every expected tool is present. Run after `docker build`:

    uv run python scripts/test_container.py [image]
"""

from __future__ import annotations

import json
import subprocess
import sys

EXPECTED_TOOLS = {
    "get_scope", "discover_hosts", "quick_scan", "port_scan", "service_scan",
    "os_detect", "script_scan", "network_inventory", "host_summary",
    "ssl_audit", "http_audit", "ssh_audit", "smb_audit", "rdp_audit",
    "dns_audit", "database_audit", "vuln_scan", "list_scans", "get_scan",
    "diff_scans", "diff_latest",
}


def _send(proc: subprocess.Popen, message: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def _recv(proc: subprocess.Popen) -> dict:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"Container closed stdout with no response. stderr:\n{stderr}")
    return json.loads(line)


def main() -> int:
    image = sys.argv[1] if len(sys.argv) > 1 else "nmap-mcp"

    proc = subprocess.Popen(
        ["docker", "run", "-i", "--rm", "-e", "NMAP_ALLOWED_TARGETS=127.0.0.1/32", image],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        _send(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-container", "version": "0.0.1"},
            },
        })
        init_response = _recv(proc)
        if "error" in init_response:
            print(f"initialize failed: {init_response['error']}", file=sys.stderr)
            return 1

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools_response = _recv(proc)
        if "error" in tools_response:
            print(f"tools/list failed: {tools_response['error']}", file=sys.stderr)
            return 1

        names = {t["name"] for t in tools_response["result"]["tools"]}
        missing = EXPECTED_TOOLS - names
        if missing:
            print(f"Missing expected tools: {sorted(missing)}", file=sys.stderr)
            return 1

        print(f"OK: {len(names)} tools registered, including all {len(EXPECTED_TOOLS)} expected.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())

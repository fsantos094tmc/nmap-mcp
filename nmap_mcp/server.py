"""MCP tool definitions. Thin by design: every tool validates nothing itself
and crafts no nmap flags itself — it calls scope.py / scripts.py / runner.py
/ history.py / format.py and returns a string. All scan tools record history
and include their scan_id."""

from __future__ import annotations

import asyncio
import subprocess
import sys

from . import config, format, history, models, runner
from . import scope as scope_mod
from . import scripts as scripts_mod
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nmap-mcp")

_cfg: config.Config | None = None
_engine: runner.NmapRunner | None = None
_catalog: scripts_mod.ScriptCatalog | None = None
_catalog_error: str | None = None
_protocol_scripts: dict[str, list[str]] = {}
_protocol_script_errors: dict[str, str] = {}


def _init() -> None:
    global _cfg, _engine, _catalog, _catalog_error
    _cfg = config.get_config()
    config.log_effective_config(_cfg)
    _engine = runner.NmapRunner(_cfg)

    try:
        _catalog = scripts_mod.load_catalog()
    except Exception as exc:  # nmap not installed, script.db missing/unreadable, etc.
        _catalog = None
        _catalog_error = str(exc)
        print(f"nmap-mcp: WARNING - NSE script catalog unavailable: {exc}", file=sys.stderr)
        return

    for tool_name, (required, optional) in runner.PROTOCOL_SCRIPTS.items():
        try:
            _protocol_scripts[tool_name] = scripts_mod.resolve_protocol_scripts(
                _catalog, required, optional
            )
        except RuntimeError as exc:
            _protocol_script_errors[tool_name] = str(exc)
            print(f"nmap-mcp: WARNING - {tool_name} scripts unavailable: {exc}", file=sys.stderr)


def _ensure_init() -> None:
    if _cfg is None:
        _init()


def reset_state() -> None:
    """Test hook: clear cached globals so the next call re-reads config/catalog."""

    global _cfg, _engine, _catalog, _catalog_error
    _cfg = None
    _engine = None
    _catalog = None
    _catalog_error = None
    _protocol_scripts.clear()
    _protocol_script_errors.clear()
    config.reset_config_cache()


def _scripts_for(tool_name: str) -> list[str] | None:
    if _catalog is None or tool_name in _protocol_script_errors:
        return None
    return _protocol_scripts.get(tool_name, [])


def _scripts_error(tool_name: str) -> str:
    return _protocol_script_errors.get(tool_name, _catalog_error or "unknown error")


def _get_nmap_version() -> str | None:
    assert _engine is not None
    try:
        proc = subprocess.run(
            [_engine.nmap_path, "-V"], capture_output=True, text=True, timeout=5
        )
        lines = proc.stdout.splitlines()
        return lines[0] if lines else None
    except Exception:
        return None


async def _run_and_record(tool: str, resolved: scope_mod.ResolvedTarget, argv_tail: list[str]) -> str:
    assert _engine is not None and _cfg is not None
    outcome = await _engine.run(
        argv_tail, tool=tool, target_display=resolved.display, resolved_targets=resolved.nmap_targets
    )
    summary = format.summarize_scan(outcome.result, tool=tool, target_display=resolved.display)
    scan_id = await asyncio.to_thread(
        history.record_scan,
        _cfg.history_db,
        models.ScanRecord(
            tool=tool,
            target=resolved.original,
            resolved_targets=list(resolved.nmap_targets),
            argv=outcome.argv,
            duration_seconds=outcome.duration_seconds,
            exit_code=outcome.exit_code,
            timed_out=outcome.timed_out,
            result=outcome.result,
            summary=summary,
        ),
    )
    note = "\n[scan timed out; results may be partial]" if outcome.timed_out else ""
    if outcome.parse_error:
        note += f"\n[warning: could not fully parse nmap output: {outcome.parse_error}]"
    body = f"{summary}{note}\n\nscan_id={scan_id}\n```json\n{outcome.result.model_dump_json(indent=2)}\n```"
    return format.truncate(body, _cfg.max_output_chars)


# --------------------------------------------------------------------------
# get_scope
# --------------------------------------------------------------------------

@mcp.tool()
def get_scope() -> str:
    """Show the configured scan scope, limits, and whether intrusive scripts are enabled."""
    _ensure_init()
    assert _cfg is not None
    return format.format_scope(_cfg, _get_nmap_version())


# --------------------------------------------------------------------------
# Phase 1: core tools
# --------------------------------------------------------------------------

@mcp.tool()
async def discover_hosts(target: str) -> str:
    """Ping-sweep a target (IP, CIDR, or hostname) to find live hosts without port scanning."""
    _ensure_init()
    assert _cfg is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_discover_argv(_cfg, resolved.nmap_targets)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("discover_hosts", resolved, argv_tail)


@mcp.tool()
async def quick_scan(target: str, top_ports: int = 100) -> str:
    """Scan the N most common TCP ports (default 100, max 1000) on a target."""
    _ensure_init()
    assert _cfg is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_quick_scan_argv(_cfg, resolved.nmap_targets, top_ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("quick_scan", resolved, argv_tail)


@mcp.tool()
async def port_scan(target: str, ports: str, scan_type: str = "syn") -> str:
    """Scan specific TCP/UDP ports on a target; scan_type is one of syn, connect, udp."""
    _ensure_init()
    assert _cfg is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_port_scan_argv(_cfg, resolved.nmap_targets, scan_type, ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("port_scan", resolved, argv_tail)


@mcp.tool()
async def service_scan(target: str, ports: str = "", intensity: int = 7) -> str:
    """Detect service names/versions on open ports (intensity 0-9, higher is slower but more accurate)."""
    _ensure_init()
    assert _cfg is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_service_scan_argv(_cfg, resolved.nmap_targets, ports, intensity)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("service_scan", resolved, argv_tail)


@mcp.tool()
async def os_detect(target: str) -> str:
    """Guess the target's operating system using TCP/IP stack fingerprinting."""
    _ensure_init()
    assert _cfg is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_os_detect_argv(_cfg, resolved.nmap_targets)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("os_detect", resolved, argv_tail)


@mcp.tool()
async def script_scan(target: str, scripts: str, ports: str = "") -> str:
    """Run allowlisted NSE scripts or categories (comma-separated) against a target."""
    _ensure_init()
    assert _cfg is not None
    if _catalog is None:
        return f"Error: NSE script catalog is unavailable ({_catalog_error}); script_scan is disabled."
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        resolved_scripts = scripts_mod.resolve_scripts(scripts, _catalog, include_intrusive=False)
        argv_tail = runner.build_script_scan_argv(_cfg, resolved.nmap_targets, resolved_scripts, ports)
    except (scope_mod.ScopeError, runner.RunnerError, scripts_mod.ScriptError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("script_scan", resolved, argv_tail)


# --------------------------------------------------------------------------
# Phase 2: workflows and protocol audits
# --------------------------------------------------------------------------

@mcp.tool()
async def network_inventory(target: str) -> str:
    """Sweep a target for live hosts, then run a quick service scan on just the hosts that respond."""
    _ensure_init()
    assert _cfg is not None and _engine is not None
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        sweep_argv = runner.build_discover_argv(_cfg, resolved.nmap_targets)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"

    sweep = await _engine.run(
        sweep_argv, tool="network_inventory.sweep",
        target_display=resolved.display, resolved_targets=resolved.nmap_targets,
    )
    live_ips = [h.address for h in sweep.result.hosts_up if h.address]

    if not live_ips:
        summary = f"network_inventory on {resolved.display}: 0 hosts up (sweep only)"
        scan_id = await asyncio.to_thread(
            history.record_scan, _cfg.history_db,
            models.ScanRecord(
                tool="network_inventory", target=resolved.original,
                resolved_targets=list(resolved.nmap_targets), argv=sweep.argv,
                duration_seconds=sweep.duration_seconds, exit_code=sweep.exit_code,
                timed_out=sweep.timed_out, result=sweep.result, summary=summary,
            ),
        )
        return format.truncate(f"{summary}\n\nscan_id={scan_id}", _cfg.max_output_chars)

    try:
        service_argv = runner.build_service_sweep_argv(_cfg, live_ips, top_ports=100)
    except runner.RunnerError as exc:
        return f"Error: {exc}"

    service = await _engine.run(
        service_argv, tool="network_inventory.services",
        target_display=resolved.display, resolved_targets=tuple(live_ips),
    )

    summary = format.summarize_scan(service.result, tool="network_inventory", target_display=resolved.display)
    scan_id = await asyncio.to_thread(
        history.record_scan, _cfg.history_db,
        models.ScanRecord(
            tool="network_inventory", target=resolved.original,
            resolved_targets=list(resolved.nmap_targets), argv=sweep.argv + service.argv,
            duration_seconds=sweep.duration_seconds + service.duration_seconds,
            exit_code=service.exit_code, timed_out=sweep.timed_out or service.timed_out,
            result=service.result, summary=summary,
        ),
    )
    body = f"{summary}\n\nscan_id={scan_id}\n```json\n{service.result.model_dump_json(indent=2)}\n```"
    return format.truncate(body, _cfg.max_output_chars)


@mcp.tool()
async def host_summary(target: str) -> str:
    """Produce a readable report for a target: OS guess, open ports, versions, default script findings."""
    _ensure_init()
    assert _cfg is not None and _engine is not None
    if _catalog is None:
        return f"Error: NSE script catalog is unavailable ({_catalog_error}); host_summary is disabled."
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_host_summary_argv(_cfg, resolved.nmap_targets, _catalog.allowed_default())
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"

    outcome = await _engine.run(
        argv_tail, tool="host_summary", target_display=resolved.display, resolved_targets=resolved.nmap_targets
    )
    report = format.format_host_report(outcome.result, resolved.display)
    scan_id = await asyncio.to_thread(
        history.record_scan, _cfg.history_db,
        models.ScanRecord(
            tool="host_summary", target=resolved.original, resolved_targets=list(resolved.nmap_targets),
            argv=outcome.argv, duration_seconds=outcome.duration_seconds, exit_code=outcome.exit_code,
            timed_out=outcome.timed_out, result=outcome.result, summary=report,
        ),
    )
    body = f"{report}\n\nscan_id={scan_id}\n```json\n{outcome.result.model_dump_json(indent=2)}\n```"
    return format.truncate(body, _cfg.max_output_chars)


def _protocol_tool_error(tool_name: str) -> str:
    return f"Error: {tool_name} scripts unavailable: {_scripts_error(tool_name)}"


@mcp.tool()
async def ssl_audit(target: str, ports: str = "443") -> str:
    """Check TLS/SSL configuration (certificate, cipher suites, clock skew) on a target."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("ssl_audit")
    if scripts_list is None:
        return _protocol_tool_error("ssl_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_ssl_audit_argv(_cfg, resolved.nmap_targets, scripts_list, ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("ssl_audit", resolved, argv_tail)


@mcp.tool()
async def http_audit(target: str, ports: str = "80,443") -> str:
    """Check HTTP title, headers, server banner, allowed methods, and robots.txt on a target."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("http_audit")
    if scripts_list is None:
        return _protocol_tool_error("http_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_http_audit_argv(_cfg, resolved.nmap_targets, scripts_list, ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("http_audit", resolved, argv_tail)


@mcp.tool()
async def ssh_audit(target: str, ports: str = "22") -> str:
    """Check SSH algorithm support and host key fingerprints on a target."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("ssh_audit")
    if scripts_list is None:
        return _protocol_tool_error("ssh_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_ssh_audit_argv(_cfg, resolved.nmap_targets, scripts_list, ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("ssh_audit", resolved, argv_tail)


@mcp.tool()
async def smb_audit(target: str) -> str:
    """Check SMB protocol versions and security mode settings on a target."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("smb_audit")
    if scripts_list is None:
        return _protocol_tool_error("smb_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_smb_audit_argv(_cfg, resolved.nmap_targets, scripts_list)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("smb_audit", resolved, argv_tail)


@mcp.tool()
async def rdp_audit(target: str) -> str:
    """Check RDP encryption level and NTLM identity info exposed by a target."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("rdp_audit")
    if scripts_list is None:
        return _protocol_tool_error("rdp_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_rdp_audit_argv(_cfg, resolved.nmap_targets, scripts_list)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("rdp_audit", resolved, argv_tail)


@mcp.tool()
async def dns_audit(target: str) -> str:
    """Check whether a target's DNS service allows open recursion and expose its NSID."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("dns_audit")
    if scripts_list is None:
        return _protocol_tool_error("dns_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_dns_audit_argv(_cfg, resolved.nmap_targets, scripts_list)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("dns_audit", resolved, argv_tail)


@mcp.tool()
async def database_audit(target: str) -> str:
    """Check for exposed MySQL, MSSQL, MongoDB, and Redis instances on a target (no brute force)."""
    _ensure_init()
    assert _cfg is not None
    scripts_list = _scripts_for("database_audit")
    if scripts_list is None:
        return _protocol_tool_error("database_audit")
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_database_audit_argv(_cfg, resolved.nmap_targets, scripts_list)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"
    return await _run_and_record("database_audit", resolved, argv_tail)


@mcp.tool()
async def vuln_scan(target: str, ports: str = "") -> str:
    """Run vulnerability-detection scripts: safe-tagged only, or full vuln category if NMAP_ALLOW_INTRUSIVE=1."""
    _ensure_init()
    assert _cfg is not None
    if _catalog is None:
        return f"Error: NSE script catalog is unavailable ({_catalog_error}); vuln_scan is disabled."
    vuln_scripts = _catalog.allowed_intrusive() if _cfg.allow_intrusive else _catalog.safe_vuln()
    if not vuln_scripts:
        return "Error: no vuln scripts are available/allowed on this nmap install."
    try:
        resolved = scope_mod.resolve_target(target, _cfg)
        argv_tail = runner.build_vuln_scan_argv(_cfg, resolved.nmap_targets, vuln_scripts, ports)
    except (scope_mod.ScopeError, runner.RunnerError) as exc:
        return f"Error: {exc}"

    mode = "intrusive" if _cfg.allow_intrusive else "safe"
    outcome = await _engine.run(
        argv_tail, tool="vuln_scan", target_display=resolved.display, resolved_targets=resolved.nmap_targets
    )
    summary = f"[{mode} mode] " + format.summarize_scan(outcome.result, tool="vuln_scan", target_display=resolved.display)
    scan_id = await asyncio.to_thread(
        history.record_scan, _cfg.history_db,
        models.ScanRecord(
            tool="vuln_scan", target=resolved.original, resolved_targets=list(resolved.nmap_targets),
            argv=outcome.argv, duration_seconds=outcome.duration_seconds, exit_code=outcome.exit_code,
            timed_out=outcome.timed_out, result=outcome.result, summary=summary,
        ),
    )
    note = "\n[scan timed out; results may be partial]" if outcome.timed_out else ""
    body = f"{summary}{note}\n\nscan_id={scan_id}\n```json\n{outcome.result.model_dump_json(indent=2)}\n```"
    return format.truncate(body, _cfg.max_output_chars)


# --------------------------------------------------------------------------
# Phase 3: history and diffing
# --------------------------------------------------------------------------

@mcp.tool()
async def list_scans(limit: int = 20, target: str = "") -> str:
    """List recent scans, optionally filtered by target, newest first."""
    _ensure_init()
    assert _cfg is not None
    records = await asyncio.to_thread(history.list_scans, _cfg.history_db, limit, target)
    return format.truncate(format.format_scan_list(records), _cfg.max_output_chars)


@mcp.tool()
async def get_scan(scan_id: int) -> str:
    """Retrieve the full stored result for a previously run scan by its id."""
    _ensure_init()
    assert _cfg is not None
    record = await asyncio.to_thread(history.get_scan, _cfg.history_db, scan_id)
    if record is None:
        return f"Error: no scan with id {scan_id}."
    body = (
        f"Scan #{record.id}: {record.tool} on {record.target} "
        f"({record.created_at:%Y-%m-%d %H:%M:%S})\n\n{record.summary}\n\n"
        f"```json\n{record.result.model_dump_json(indent=2)}\n```"
    )
    return format.truncate(body, _cfg.max_output_chars)


@mcp.tool()
async def diff_scans(scan_id_a: int, scan_id_b: int) -> str:
    """Diff two previously run scans by id: hosts up/down, port and OS changes."""
    _ensure_init()
    assert _cfg is not None
    try:
        diff = await asyncio.to_thread(history.diff_scans, _cfg.history_db, scan_id_a, scan_id_b)
    except history.HistoryError as exc:
        return f"Error: {exc}"
    return format.truncate(format.format_diff(diff), _cfg.max_output_chars)


@mcp.tool()
async def diff_latest(target: str) -> str:
    """Diff the two most recent scans of the same target and tool."""
    _ensure_init()
    assert _cfg is not None
    try:
        diff = await asyncio.to_thread(history.diff_latest, _cfg.history_db, target)
    except history.HistoryError as exc:
        return f"Error: {exc}"
    return format.truncate(format.format_diff(diff), _cfg.max_output_chars)


def main() -> None:
    _init()
    mcp.run()


if __name__ == "__main__":
    main()

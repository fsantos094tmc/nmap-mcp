"""Human-readable summaries rendered ahead of the JSON block in tool output."""

from __future__ import annotations

from .config import Config
from .models import ScanDiff, ScanRecord, ScanResult


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return text[:max_chars] + f"\n... [truncated, {omitted} more characters]"


def summarize_scan(result: ScanResult, *, tool: str, target_display: str) -> str:
    up = result.hosts_up
    total = len(result.hosts) or len(up)
    lines = [f"{tool} on {target_display}: {len(up)}/{total} host(s) up"]

    for host in up[:20]:
        addr = host.address or "?"
        hostnames = f" ({', '.join(host.hostnames)})" if host.hostnames else ""
        open_ports = host.open_ports
        port_bits = [
            f"{p.port_id}/{p.protocol}" + (f" {p.service.name}" if p.service and p.service.name else "")
            for p in open_ports[:15]
        ]
        extra = f" (+{len(open_ports) - 15} more)" if len(open_ports) > 15 else ""
        lines.append(f"  {addr}{hostnames}: {', '.join(port_bits) or 'no open ports found'}{extra}")

    if len(up) > 20:
        lines.append(f"  ... and {len(up) - 20} more host(s) up")

    return "\n".join(lines)


def format_host_report(result: ScanResult, target_display: str) -> str:
    lines = [f"Host summary for {target_display}:"]

    if not result.hosts_up:
        lines.append("  No hosts responded as up.")
        return "\n".join(lines)

    for host in result.hosts_up:
        addr = host.address or "?"
        names = ", ".join(host.hostnames) or "no hostname"
        lines.append(f"\n{addr} ({names}) - {host.state}")

        if host.os_matches:
            top = host.os_matches[0]
            lines.append(f"  OS guess: {top.name} (accuracy {top.accuracy}%)")

        if host.open_ports:
            lines.append("  Open ports:")
            for port in host.open_ports:
                svc = " ".join(filter(None, [port.service.name, port.service.product, port.service.version])) if port.service else ""
                lines.append(f"    {port.port_id}/{port.protocol} {port.state} {svc}".rstrip())

        script_hits = [s for s in host.scripts if s.output.strip()]
        script_hits += [s for p in host.ports for s in p.scripts if s.output.strip()]
        if script_hits:
            lines.append("  Script findings:")
            for s in script_hits[:10]:
                snippet = s.output.strip().splitlines()[0][:200]
                lines.append(f"    [{s.id}] {snippet}")

    return "\n".join(lines)


def format_scan_list(records: list[ScanRecord]) -> str:
    if not records:
        return "No scans recorded yet."
    lines = ["Recent scans:"]
    for r in records:
        hosts_up = len(r.result.hosts_up)
        open_ports = sum(len(h.open_ports) for h in r.result.hosts)
        lines.append(
            f"  #{r.id} [{r.created_at:%Y-%m-%d %H:%M:%S}] {r.tool} target={r.target} "
            f"hosts_up={hosts_up} open_ports={open_ports} duration={r.duration_seconds:.1f}s"
            + (" (timed out)" if r.timed_out else "")
        )
    return "\n".join(lines)


def format_diff(diff: ScanDiff) -> str:
    lines = [f"Diff of scan #{diff.scan_id_a} -> #{diff.scan_id_b} for {diff.target}:"]

    if diff.hosts_up_in_b_only:
        lines.append(f"  Hosts newly up: {', '.join(diff.hosts_up_in_b_only)}")
    if diff.hosts_down_in_b_only:
        lines.append(f"  Hosts newly down: {', '.join(diff.hosts_down_in_b_only)}")

    changed = [hd for hd in diff.host_diffs if hd.port_changes or hd.change == "os_changed"]
    if not changed and not diff.hosts_up_in_b_only and not diff.hosts_down_in_b_only:
        lines.append("  No differences detected.")

    for hd in changed:
        lines.append(f"  {hd.address}:")
        if hd.change == "os_changed":
            lines.append(f"    OS changed: {hd.os_before!r} -> {hd.os_after!r}")
        for pc in hd.port_changes:
            lines.append(f"    {pc.port_id}/{pc.protocol} {pc.change}: {pc.before!r} -> {pc.after!r}")

    return "\n".join(lines)


def format_scope(cfg: Config, nmap_version: str | None = None) -> str:
    lines = [
        "Scan scope:",
        f"  Allowed targets: {', '.join(cfg.allowed_targets) or '(none configured - all scans refused)'}",
        f"  Denied targets: {', '.join(cfg.deny_targets) or '(none)'}",
        f"  Max hosts per scan: {cfg.max_hosts}",
        f"  Max timeout per scan: {cfg.timeout}s",
        f"  Max parallel scans: {cfg.max_parallel}",
        f"  Max timing template: T{cfg.max_timing}",
        f"  Intrusive/vuln scripts: {'enabled' if cfg.allow_intrusive else 'disabled'}",
    ]
    if nmap_version:
        lines.append(f"  nmap version: {nmap_version}")
    return "\n".join(lines)

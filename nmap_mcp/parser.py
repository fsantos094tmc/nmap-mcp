"""nmap XML (-oX -) -> typed :class:`~nmap_mcp.models.ScanResult`."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .models import (
    Host,
    OSClass,
    OSMatch,
    Port,
    RunStats,
    ScanResult,
    Service,
    ScriptResult,
    ScriptTable,
    TraceHop,
)


class ParserError(ValueError):
    """nmap's XML output could not be parsed."""


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _epoch_or_none(value: str | None) -> datetime | None:
    ts = _int_or_none(value)
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def parse_nmap_xml(xml_text: str) -> ScanResult:
    """Parse a complete ``-oX -`` document. Raises :class:`ParserError` on
    malformed/incomplete XML (e.g. output truncated by a killed scan)."""

    if not xml_text or not xml_text.strip():
        return ScanResult()

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ParserError(f"Could not parse nmap XML output: {exc}") from exc

    hosts = [_parse_host(host_el) for host_el in root.findall("host")]
    run_stats = _parse_run_stats(root)
    return ScanResult(hosts=hosts, run_stats=run_stats)


def _parse_host(host_el: ET.Element) -> Host:
    status_el = host_el.find("status")
    state = status_el.get("state", "unknown") if status_el is not None else "unknown"
    reason = status_el.get("reason") if status_el is not None else None

    ipv4 = ipv6 = mac = mac_vendor = None
    for addr_el in host_el.findall("address"):
        addrtype = addr_el.get("addrtype")
        if addrtype == "ipv4":
            ipv4 = addr_el.get("addr")
        elif addrtype == "ipv6":
            ipv6 = addr_el.get("addr")
        elif addrtype == "mac":
            mac = addr_el.get("addr")
            mac_vendor = addr_el.get("vendor")

    hostnames = [
        hn.get("name", "")
        for hn in host_el.findall("hostnames/hostname")
        if hn.get("name")
    ]

    ports = [_parse_port(port_el) for port_el in host_el.findall("ports/port")]

    os_matches: list[OSMatch] = []
    os_el = host_el.find("os")
    if os_el is not None:
        for osmatch_el in os_el.findall("osmatch"):
            classes = [
                OSClass(
                    type=osclass_el.get("type"),
                    vendor=osclass_el.get("vendor"),
                    osfamily=osclass_el.get("osfamily"),
                    osgen=osclass_el.get("osgen"),
                    accuracy=_int_or_none(osclass_el.get("accuracy")),
                )
                for osclass_el in osmatch_el.findall("osclass")
            ]
            os_matches.append(
                OSMatch(
                    name=osmatch_el.get("name", ""),
                    accuracy=_int_or_none(osmatch_el.get("accuracy")),
                    line=osmatch_el.get("line"),
                    classes=classes,
                )
            )

    uptime_el = host_el.find("uptime")
    uptime_seconds = (
        _int_or_none(uptime_el.get("seconds")) if uptime_el is not None else None
    )

    distance_el = host_el.find("distance")
    distance = _int_or_none(distance_el.get("value")) if distance_el is not None else None

    host_scripts = [_parse_script(s) for s in host_el.findall("hostscript/script")]

    trace: list[TraceHop] = []
    trace_el = host_el.find("trace")
    if trace_el is not None:
        for hop_el in trace_el.findall("hop"):
            trace.append(
                TraceHop(
                    ttl=_int_or_none(hop_el.get("ttl")),
                    ip_address=hop_el.get("ipaddr"),
                    rtt_ms=_float_or_none(hop_el.get("rtt")),
                    host=hop_el.get("host"),
                )
            )

    return Host(
        state=state,
        reason=reason,
        ipv4=ipv4,
        ipv6=ipv6,
        mac=mac,
        mac_vendor=mac_vendor,
        hostnames=hostnames,
        uptime_seconds=uptime_seconds,
        distance=distance,
        ports=ports,
        os_matches=os_matches,
        scripts=host_scripts,
        trace=trace,
    )


def _parse_port(port_el: ET.Element) -> Port:
    state_el = port_el.find("state")
    service_el = port_el.find("service")

    service = None
    if service_el is not None:
        cpes = [c.text for c in service_el.findall("cpe") if c.text]
        service = Service(
            name=service_el.get("name"),
            product=service_el.get("product"),
            version=service_el.get("version"),
            extrainfo=service_el.get("extrainfo"),
            ostype=service_el.get("ostype"),
            method=service_el.get("method"),
            conf=_int_or_none(service_el.get("conf")),
            cpes=cpes,
        )

    scripts = [_parse_script(s) for s in port_el.findall("script")]

    return Port(
        protocol=port_el.get("protocol", ""),
        port_id=int(port_el.get("portid", "0")),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
        reason=state_el.get("reason") if state_el is not None else None,
        service=service,
        scripts=scripts,
    )


def _parse_table(table_el: ET.Element) -> ScriptTable:
    elements = {
        (elem_el.get("key") or ""): (elem_el.text or "")
        for elem_el in table_el.findall("elem")
    }
    nested = [_parse_table(t) for t in table_el.findall("table")]
    return ScriptTable(key=table_el.get("key"), elements=elements, tables=nested)


def _parse_script(script_el: ET.Element) -> ScriptResult:
    tables = [_parse_table(t) for t in script_el.findall("table")]
    return ScriptResult(
        id=script_el.get("id", ""),
        output=script_el.get("output") or "",
        tables=tables,
    )


def _parse_run_stats(root: ET.Element) -> RunStats:
    finished_el = root.find("runstats/finished")
    end_time = elapsed = exit_status = None
    if finished_el is not None:
        end_time = _epoch_or_none(finished_el.get("time"))
        elapsed = _float_or_none(finished_el.get("elapsed"))
        exit_status = finished_el.get("exit")

    hosts_el = root.find("runstats/hosts")
    hosts_up = hosts_down = hosts_total = 0
    if hosts_el is not None:
        hosts_up = _int_or_none(hosts_el.get("up")) or 0
        hosts_down = _int_or_none(hosts_el.get("down")) or 0
        hosts_total = _int_or_none(hosts_el.get("total")) or 0

    return RunStats(
        scanner=root.get("scanner"),
        args=root.get("args"),
        version=root.get("version"),
        start_time=_epoch_or_none(root.get("start")),
        end_time=end_time,
        elapsed_seconds=elapsed,
        exit_status=exit_status,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        hosts_total=hosts_total,
    )

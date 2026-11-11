"""SQLite-backed scan history and diffing.

All functions here are synchronous (sqlite3 is sync); server.py calls them
via ``asyncio.to_thread`` so the event loop never blocks on disk I/O.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import Host, HostDiff, Port, PortChange, ScanDiff, ScanRecord, ScanResult

MAX_HISTORY = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    resolved_targets TEXT NOT NULL,
    argv TEXT NOT NULL,
    created_at TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    exit_code INTEGER,
    timed_out INTEGER NOT NULL,
    result TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target_tool ON scans(target, tool, created_at);
"""


class HistoryError(ValueError):
    """A scan id or target could not be resolved in history."""


def _connect(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def _row_to_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=row["id"],
        tool=row["tool"],
        target=row["target"],
        resolved_targets=json.loads(row["resolved_targets"]),
        argv=json.loads(row["argv"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        duration_seconds=row["duration_seconds"],
        exit_code=row["exit_code"],
        timed_out=bool(row["timed_out"]),
        result=ScanResult.model_validate_json(row["result"]),
        summary=row["summary"],
    )


def _trim_history(conn: sqlite3.Connection) -> None:
    (count,) = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    if count > MAX_HISTORY:
        excess = count - MAX_HISTORY
        conn.execute(
            "DELETE FROM scans WHERE id IN "
            "(SELECT id FROM scans ORDER BY created_at ASC, id ASC LIMIT ?)",
            (excess,),
        )


def record_scan(db_path: Path | str, record: ScanRecord) -> int:
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scans "
            "(tool, target, resolved_targets, argv, created_at, duration_seconds, "
            " exit_code, timed_out, result, summary) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                record.tool,
                record.target,
                json.dumps(list(record.resolved_targets)),
                json.dumps(list(record.argv)),
                record.created_at.isoformat(),
                record.duration_seconds,
                record.exit_code,
                int(record.timed_out),
                record.result.model_dump_json(),
                record.summary,
            ),
        )
        new_id = cur.lastrowid
        _trim_history(conn)
        conn.commit()
        return new_id


def get_scan(db_path: Path | str, scan_id: int) -> ScanRecord | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_record(row) if row else None


def list_scans(db_path: Path | str, limit: int = 20, target: str = "") -> list[ScanRecord]:
    with _connect(db_path) as conn:
        if target:
            rows = conn.execute(
                "SELECT * FROM scans WHERE target = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_record(r) for r in rows]


def _service_str(port: Port) -> str | None:
    if port.service is None:
        return None
    parts = [p for p in (port.service.name, port.service.product, port.service.version) if p]
    return " ".join(parts) if parts else None


def _diff_ports(host_a: Host | None, host_b: Host | None) -> list[PortChange]:
    def index(host: Host | None) -> dict[tuple[str, int], Port]:
        return {(p.protocol, p.port_id): p for p in host.ports} if host else {}

    pa, pb = index(host_a), index(host_b)
    changes: list[PortChange] = []
    for key in sorted(set(pa) | set(pb)):
        a, b = pa.get(key), pb.get(key)
        a_open = a is not None and a.state == "open"
        b_open = b is not None and b.state == "open"
        protocol, port_id = key

        if b_open and not a_open:
            changes.append(
                PortChange(protocol=protocol, port_id=port_id, change="opened", after=_service_str(b))
            )
        elif a_open and not b_open:
            changes.append(
                PortChange(protocol=protocol, port_id=port_id, change="closed", before=_service_str(a))
            )
        elif a_open and b_open:
            before, after = _service_str(a), _service_str(b)
            if before != after:
                changes.append(
                    PortChange(
                        protocol=protocol, port_id=port_id, change="service_changed",
                        before=before, after=after,
                    )
                )
    return changes


def diff_scan_results(
    scan_id_a: int, scan_id_b: int, target: str, result_a: ScanResult, result_b: ScanResult
) -> ScanDiff:
    hosts_a = {h.address: h for h in result_a.hosts if h.address}
    hosts_b = {h.address: h for h in result_b.hosts if h.address}

    hosts_up_in_b_only: list[str] = []
    hosts_down_in_b_only: list[str] = []
    host_diffs: list[HostDiff] = []

    for addr in sorted(set(hosts_a) | set(hosts_b)):
        host_a, host_b = hosts_a.get(addr), hosts_b.get(addr)
        a_up = host_a is not None and host_a.state == "up"
        b_up = host_b is not None and host_b.state == "up"

        if b_up and not a_up:
            hosts_up_in_b_only.append(addr)
            host_diffs.append(HostDiff(address=addr, change="host_up"))
            continue
        if a_up and not b_up:
            hosts_down_in_b_only.append(addr)
            host_diffs.append(HostDiff(address=addr, change="host_down"))
            continue
        if not (a_up and b_up):
            continue

        os_before = host_a.os_matches[0].name if host_a.os_matches else None
        os_after = host_b.os_matches[0].name if host_b.os_matches else None
        port_changes = _diff_ports(host_a, host_b)
        host_diffs.append(
            HostDiff(
                address=addr,
                change="os_changed" if os_before != os_after else "unchanged",
                port_changes=port_changes,
                os_before=os_before,
                os_after=os_after,
            )
        )

    return ScanDiff(
        scan_id_a=scan_id_a,
        scan_id_b=scan_id_b,
        target=target,
        hosts_up_in_b_only=hosts_up_in_b_only,
        hosts_down_in_b_only=hosts_down_in_b_only,
        host_diffs=host_diffs,
    )


def diff_scans(db_path: Path | str, scan_id_a: int, scan_id_b: int) -> ScanDiff:
    record_a = get_scan(db_path, scan_id_a)
    record_b = get_scan(db_path, scan_id_b)
    if record_a is None:
        raise HistoryError(f"No scan with id {scan_id_a}.")
    if record_b is None:
        raise HistoryError(f"No scan with id {scan_id_b}.")
    return diff_scan_results(scan_id_a, scan_id_b, record_b.target, record_a.result, record_b.result)


def diff_latest(db_path: Path | str, target: str) -> ScanDiff:
    rows = list_scans(db_path, limit=50, target=target)
    if not rows:
        raise HistoryError(f"No scans recorded for target {target!r}.")
    latest_tool = rows[0].tool
    matching = [r for r in rows if r.tool == latest_tool]
    if len(matching) < 2:
        raise HistoryError(
            f"Only one scan with tool {latest_tool!r} recorded for target {target!r}; "
            "need at least two to diff."
        )
    newer, older = matching[0], matching[1]
    return diff_scans(db_path, older.id, newer.id)

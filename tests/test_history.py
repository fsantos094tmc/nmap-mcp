from __future__ import annotations

from pathlib import Path

import pytest

from nmap_mcp.history import HistoryError, diff_latest, diff_scans, get_scan, list_scans, record_scan
from nmap_mcp.models import Host, Port, Service, ScanRecord, ScanResult


def _scan_record(tool: str, target: str, hosts: list[Host]) -> ScanRecord:
    return ScanRecord(
        tool=tool,
        target=target,
        resolved_targets=[target],
        argv=["nmap", "-oX", "-"],
        duration_seconds=1.0,
        exit_code=0,
        timed_out=False,
        result=ScanResult(hosts=hosts),
        summary="test",
    )


def _host(addr: str, *, up: bool = True, ports: list[Port] | None = None, os_name: str | None = None):
    from nmap_mcp.models import OSMatch

    return Host(
        state="up" if up else "down",
        ipv4=addr,
        ports=ports or [],
        os_matches=[OSMatch(name=os_name)] if os_name else [],
    )


def _port(port_id: int, *, open_: bool = True, name: str | None = None, product: str | None = None) -> Port:
    service = Service(name=name, product=product) if (name or product) else None
    return Port(protocol="tcp", port_id=port_id, state="open" if open_ else "closed", service=service)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


def test_record_and_get_scan_roundtrip(db_path):
    record = _scan_record("quick_scan", "10.0.0.5", [_host("10.0.0.5", ports=[_port(80)])])
    scan_id = record_scan(db_path, record)
    assert scan_id == 1

    fetched = get_scan(db_path, scan_id)
    assert fetched is not None
    assert fetched.tool == "quick_scan"
    assert fetched.target == "10.0.0.5"
    assert fetched.result.hosts[0].ports[0].port_id == 80


def test_get_scan_missing_returns_none(db_path):
    assert get_scan(db_path, 999) is None


def test_list_scans_orders_newest_first_and_filters_by_target(db_path):
    record_scan(db_path, _scan_record("quick_scan", "10.0.0.5", []))
    record_scan(db_path, _scan_record("quick_scan", "10.0.0.6", []))
    record_scan(db_path, _scan_record("os_detect", "10.0.0.5", []))

    all_scans = list_scans(db_path)
    assert [r.id for r in all_scans] == [3, 2, 1]

    only_five = list_scans(db_path, target="10.0.0.5")
    assert [r.id for r in only_five] == [3, 1]


def test_history_caps_at_500_and_drops_oldest(db_path, monkeypatch):
    import nmap_mcp.history as history_mod

    monkeypatch.setattr(history_mod, "MAX_HISTORY", 5)
    ids = [record_scan(db_path, _scan_record("quick_scan", "10.0.0.5", [])) for _ in range(8)]

    remaining = list_scans(db_path, limit=100)
    assert len(remaining) == 5
    remaining_ids = {r.id for r in remaining}
    assert remaining_ids == set(ids[-5:])


def test_diff_detects_opened_closed_and_changed_ports(db_path):
    scan_a = _scan_record(
        "service_scan", "10.0.0.5",
        [_host("10.0.0.5", ports=[_port(22, name="ssh"), _port(80, name="http", product="nginx")])],
    )
    scan_b = _scan_record(
        "service_scan", "10.0.0.5",
        [
            _host(
                "10.0.0.5",
                ports=[
                    _port(80, name="http", product="apache"),  # service changed
                    _port(443),  # opened
                    # port 22 closed (absent/closed in b)
                ],
            )
        ],
    )
    id_a = record_scan(db_path, scan_a)
    id_b = record_scan(db_path, scan_b)

    diff = diff_scans(db_path, id_a, id_b)
    changes_by_port = {pc.port_id: pc.change for hd in diff.host_diffs for pc in hd.port_changes}
    assert changes_by_port[443] == "opened"
    assert changes_by_port[22] == "closed"
    assert changes_by_port[80] == "service_changed"


def test_diff_detects_host_up_and_down(db_path):
    scan_a = _scan_record("discover_hosts", "10.0.0.0/24", [_host("10.0.0.5", up=True)])
    scan_b = _scan_record(
        "discover_hosts", "10.0.0.0/24",
        [_host("10.0.0.5", up=False), _host("10.0.0.6", up=True)],
    )
    id_a = record_scan(db_path, scan_a)
    id_b = record_scan(db_path, scan_b)

    diff = diff_scans(db_path, id_a, id_b)
    assert diff.hosts_up_in_b_only == ["10.0.0.6"]
    assert diff.hosts_down_in_b_only == ["10.0.0.5"]


def test_diff_detects_os_change(db_path):
    scan_a = _scan_record("os_detect", "10.0.0.5", [_host("10.0.0.5", os_name="Linux 5.X")])
    scan_b = _scan_record("os_detect", "10.0.0.5", [_host("10.0.0.5", os_name="Linux 6.X")])
    id_a = record_scan(db_path, scan_a)
    id_b = record_scan(db_path, scan_b)

    diff = diff_scans(db_path, id_a, id_b)
    host_diff = diff.host_diffs[0]
    assert host_diff.change == "os_changed"
    assert host_diff.os_before == "Linux 5.X"
    assert host_diff.os_after == "Linux 6.X"


def test_diff_scans_raises_on_missing_id(db_path):
    id_a = record_scan(db_path, _scan_record("quick_scan", "10.0.0.5", []))
    with pytest.raises(HistoryError):
        diff_scans(db_path, id_a, 999)


def test_diff_latest_compares_two_most_recent_same_tool(db_path):
    record_scan(db_path, _scan_record("quick_scan", "10.0.0.5", [_host("10.0.0.5", ports=[_port(22)])]))
    record_scan(db_path, _scan_record("os_detect", "10.0.0.5", []))  # different tool, should be skipped
    record_scan(
        db_path,
        _scan_record("quick_scan", "10.0.0.5", [_host("10.0.0.5", ports=[_port(22), _port(80)])]),
    )

    diff = diff_latest(db_path, "10.0.0.5")
    changes_by_port = {pc.port_id: pc.change for hd in diff.host_diffs for pc in hd.port_changes}
    assert changes_by_port[80] == "opened"


def test_diff_latest_raises_when_only_one_scan_exists(db_path):
    record_scan(db_path, _scan_record("quick_scan", "10.0.0.5", []))
    with pytest.raises(HistoryError, match="need at least two"):
        diff_latest(db_path, "10.0.0.5")


def test_diff_latest_raises_when_no_scans_exist(db_path):
    with pytest.raises(HistoryError, match="No scans recorded"):
        diff_latest(db_path, "10.0.0.5")

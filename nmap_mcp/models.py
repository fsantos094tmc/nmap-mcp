"""Typed representations of parsed nmap output and stored scan history."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Service(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    ostype: str | None = None
    method: str | None = None
    conf: int | None = None
    cpes: list[str] = Field(default_factory=list)


class ScriptTable(BaseModel):
    """A single <table> inside a script's structured output."""

    key: str | None = None
    elements: dict[str, str] = Field(default_factory=dict)
    tables: list["ScriptTable"] = Field(default_factory=list)


class ScriptResult(BaseModel):
    id: str
    output: str = ""
    tables: list[ScriptTable] = Field(default_factory=list)


class Port(BaseModel):
    protocol: str
    port_id: int
    state: str
    reason: str | None = None
    service: Service | None = None
    scripts: list[ScriptResult] = Field(default_factory=list)


class OSClass(BaseModel):
    type: str | None = None
    vendor: str | None = None
    osfamily: str | None = None
    osgen: str | None = None
    accuracy: int | None = None


class OSMatch(BaseModel):
    name: str
    accuracy: int | None = None
    line: str | None = None
    classes: list[OSClass] = Field(default_factory=list)


class TraceHop(BaseModel):
    ttl: int | None = None
    ip_address: str | None = None
    rtt_ms: float | None = None
    host: str | None = None


class Host(BaseModel):
    state: str
    reason: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    mac_vendor: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    uptime_seconds: int | None = None
    distance: int | None = None
    ports: list[Port] = Field(default_factory=list)
    os_matches: list[OSMatch] = Field(default_factory=list)
    scripts: list[ScriptResult] = Field(default_factory=list)
    trace: list[TraceHop] = Field(default_factory=list)

    @property
    def address(self) -> str | None:
        return self.ipv4 or self.ipv6

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]


class RunStats(BaseModel):
    scanner: str | None = None
    args: str | None = None
    version: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    elapsed_seconds: float | None = None
    exit_status: str | None = None
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0


class ScanResult(BaseModel):
    hosts: list[Host] = Field(default_factory=list)
    run_stats: RunStats = Field(default_factory=RunStats)

    @property
    def hosts_up(self) -> list[Host]:
        return [h for h in self.hosts if h.state == "up"]


class ScanRecord(BaseModel):
    id: int | None = None
    tool: str
    target: str
    resolved_targets: list[str] = Field(default_factory=list)
    argv: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    duration_seconds: float = 0.0
    exit_code: int | None = None
    timed_out: bool = False
    result: ScanResult = Field(default_factory=ScanResult)
    summary: str = ""


class PortChange(BaseModel):
    protocol: str
    port_id: int
    change: str  # "opened" | "closed" | "service_changed"
    before: str | None = None
    after: str | None = None


class HostDiff(BaseModel):
    address: str
    change: str  # "host_up" | "host_down" | "unchanged" | "os_changed"
    port_changes: list[PortChange] = Field(default_factory=list)
    os_before: str | None = None
    os_after: str | None = None


class ScanDiff(BaseModel):
    scan_id_a: int
    scan_id_b: int
    target: str
    hosts_up_in_b_only: list[str] = Field(default_factory=list)
    hosts_down_in_b_only: list[str] = Field(default_factory=list)
    host_diffs: list[HostDiff] = Field(default_factory=list)


ScriptTable.model_rebuild()

"""Target validation: the only gate between an AI-supplied string and nmap.

A target string goes through, in order: character/shape rejection, syntax
classification (single IP / CIDR / hostname), scope-membership checks, and
DNS pinning for hostnames. Any failure raises :class:`ScopeError` — this
module fails closed by design.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Sequence

from .config import Config

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Characters that have no legitimate place in an IP/CIDR/hostname target.
FORBIDDEN_CHARS = set(";|&$`(){}<>'\"\\\n\r\t ")

#: Classic nmap last-octet range syntax, e.g. "10.0.0.1-50". CIDR notation
#: is the only supported way to express a range.
_RANGE_SYNTAX_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")

_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*\.?$"
)

Resolver = Callable[[str], Sequence[str]]


class ScopeError(ValueError):
    """A target, CIDR, or resolved address falls outside the configured scope."""


@dataclass(frozen=True)
class ResolvedTarget:
    #: Exactly what the caller passed in.
    original: str
    #: What to show a human (the hostname, if one was given; otherwise the IP/CIDR).
    display: str
    #: What to put on the nmap argv. Never a hostname — always IP(s) or a CIDR.
    nmap_targets: tuple[str, ...]
    #: Number of addresses this target covers, for NMAP_MAX_HOSTS accounting.
    host_count: int


def check_scope_configured(cfg: Config) -> None:
    """Raise if no allowlist has been set. Call this first in every scan tool."""

    if not cfg.scope_configured:
        raise ScopeError(
            "No authorized targets are configured. Set NMAP_ALLOWED_TARGETS to the "
            "CIDR(s)/IP(s) you are authorized to scan (comma-separated), then restart "
            "the server. Example: NMAP_ALLOWED_TARGETS=192.168.1.0/24,10.10.0.5"
        )


def _reject_malicious_shape(raw: str) -> None:
    if raw is None or raw.strip() == "":
        raise ScopeError("Target is empty.")
    if raw != raw.strip():
        raise ScopeError(f"Target {raw!r} has leading/trailing whitespace.")
    if "," in raw:
        raise ScopeError(
            f"Target {raw!r} looks like a list; pass exactly one IP, CIDR, or hostname."
        )
    if raw.startswith("-"):
        raise ScopeError(f"Target {raw!r} looks like an nmap flag, not a target.")
    bad = FORBIDDEN_CHARS & set(raw)
    if bad:
        raise ScopeError(f"Target {raw!r} contains forbidden characters: {sorted(bad)!r}")
    if _RANGE_SYNTAX_RE.match(raw):
        raise ScopeError(
            f"Target {raw!r} uses nmap range syntax, which is not supported; "
            "use CIDR notation instead (e.g. 10.0.0.0/24)."
        )
    if ".." in raw:
        raise ScopeError(f"Target {raw!r} contains a path-like sequence ('..').")


def _as_host_network(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> IPNetwork:
    prefix = 32 if ip.version == 4 else 128
    return ipaddress.ip_network(f"{ip}/{prefix}")


def _parse_networks(cidrs: Sequence[str]) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for cidr in cidrs:
        networks.append(ipaddress.ip_network(cidr, strict=True))
    return networks


def _is_within_allowed(network: IPNetwork, allowed: list[IPNetwork]) -> bool:
    for allowed_net in allowed:
        if allowed_net.version != network.version:
            continue
        if network.subnet_of(allowed_net):
            return True
    return False


def _overlaps_denied(network: IPNetwork, denied: list[IPNetwork]) -> bool:
    for denied_net in denied:
        if denied_net.version != network.version:
            continue
        if network.overlaps(denied_net):
            return True
    return False


def _check_network_in_scope(network: IPNetwork, cfg: Config, *, label: str) -> None:
    if network.num_addresses > cfg.max_hosts:
        raise ScopeError(
            f"{label} covers {network.num_addresses} addresses, which exceeds "
            f"NMAP_MAX_HOSTS={cfg.max_hosts}."
        )

    allowed = _parse_networks(cfg.allowed_targets)
    denied = _parse_networks(cfg.deny_targets)

    if not _is_within_allowed(network, allowed):
        raise ScopeError(
            f"{label} is not within any authorized range (NMAP_ALLOWED_TARGETS)."
        )
    if _overlaps_denied(network, denied):
        raise ScopeError(f"{label} overlaps a denied range (NMAP_DENY_TARGETS).")


def _default_resolver(hostname: str) -> list[str]:
    addresses: set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ScopeError(f"Could not resolve hostname {hostname!r}: {exc}") from exc
    for family, _type, _proto, _canon, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            addresses.add(sockaddr[0])
    if not addresses:
        raise ScopeError(f"Hostname {hostname!r} did not resolve to any address.")
    return sorted(addresses)


def resolve_target(
    raw: str, cfg: Config, *, resolver: Resolver | None = None
) -> ResolvedTarget:
    """Validate ``raw`` against scope and return what nmap should actually see.

    Hostnames are resolved and pinned to their IP(s) here; the hostname
    itself never reaches nmap, so a DNS change between this check and the
    scan can't redirect where the packets go.
    """

    check_scope_configured(cfg)
    _reject_malicious_shape(raw)

    # 1) Single IP literal.
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        ip = None
    if ip is not None:
        network = _as_host_network(ip)
        _check_network_in_scope(network, cfg, label=f"Target {raw!r}")
        return ResolvedTarget(
            original=raw, display=raw, nmap_targets=(str(ip),), host_count=1
        )

    # 2) CIDR.
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise ScopeError(f"Target {raw!r} is not a valid CIDR: {exc}") from exc
        _check_network_in_scope(network, cfg, label=f"Target {raw!r}")
        return ResolvedTarget(
            original=raw,
            display=raw,
            nmap_targets=(str(network),),
            host_count=network.num_addresses,
        )

    # 3) Hostname.
    if not _HOSTNAME_RE.match(raw):
        raise ScopeError(f"Target {raw!r} is not a valid IP, CIDR, or hostname.")

    resolve = resolver or _default_resolver
    resolved_ips = list(resolve(raw))
    if not resolved_ips:
        raise ScopeError(f"Hostname {raw!r} did not resolve to any address.")

    for ip_str in resolved_ips:
        addr = ipaddress.ip_address(ip_str)
        network = _as_host_network(addr)
        _check_network_in_scope(
            network, cfg, label=f"Hostname {raw!r} (resolves to {ip_str})"
        )

    return ResolvedTarget(
        original=raw,
        display=raw,
        nmap_targets=tuple(resolved_ips),
        host_count=len(resolved_ips),
    )

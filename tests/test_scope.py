from __future__ import annotations

import pytest

from nmap_mcp.scope import ScopeError, resolve_target


def test_empty_allowlist_refuses_everything(empty_scope_cfg):
    with pytest.raises(ScopeError, match="No authorized targets"):
        resolve_target("192.168.1.10", empty_scope_cfg)


def test_allowed_ip_passes(home_cfg):
    resolved = resolve_target("192.168.1.42", home_cfg)
    assert resolved.nmap_targets == ("192.168.1.42",)
    assert resolved.host_count == 1
    assert resolved.display == "192.168.1.42"


def test_public_ip_is_blocked(home_cfg):
    with pytest.raises(ScopeError, match="not within any authorized range"):
        resolve_target("8.8.8.8", home_cfg)


def test_cidr_within_scope_passes(home_cfg):
    # .16/28 (192.168.1.16-31) avoids the denied .1 carve-out.
    resolved = resolve_target("192.168.1.16/28", home_cfg)
    assert resolved.nmap_targets == ("192.168.1.16/28",)
    assert resolved.host_count == 16


def test_cidr_partly_outside_scope_is_blocked(home_cfg):
    from nmap_mcp.config import Config

    # Same allow/deny lists, but with enough headroom that this test isn't
    # short-circuited by the (separately tested) max-hosts check.
    cfg = Config(
        allowed_targets=home_cfg.allowed_targets,
        deny_targets=home_cfg.deny_targets,
        max_hosts=1024,
    )
    # 192.168.0.0/23 covers 192.168.0.0-192.168.1.255, only half of which is allowed.
    with pytest.raises(ScopeError, match="not within any authorized range"):
        resolve_target("192.168.0.0/23", cfg)


def test_oversize_cidr_is_blocked(home_cfg):
    with pytest.raises(ScopeError, match="exceeds NMAP_MAX_HOSTS"):
        resolve_target("10.10.0.0/23", home_cfg)  # /23 = 512 > max_hosts=256


def test_denied_carveout_is_blocked(home_cfg):
    with pytest.raises(ScopeError, match="overlaps a denied range"):
        resolve_target("192.168.1.1", home_cfg)


def test_denied_carveout_blocks_containing_cidr(home_cfg):
    with pytest.raises(ScopeError, match="overlaps a denied range"):
        resolve_target("192.168.1.0/30", home_cfg)  # contains .1.1


def test_single_allowed_host_outside_cidr_passes(home_cfg):
    resolved = resolve_target("203.0.113.5", home_cfg)
    assert resolved.nmap_targets == ("203.0.113.5",)


def test_hostname_resolving_in_scope_is_pinned_to_ip(home_cfg):
    resolved = resolve_target(
        "nas.lan", home_cfg, resolver=lambda host: ["192.168.1.50"]
    )
    assert resolved.nmap_targets == ("192.168.1.50",)
    assert resolved.display == "nas.lan"
    assert resolved.original == "nas.lan"


def test_hostname_resolving_out_of_scope_is_blocked(home_cfg):
    with pytest.raises(ScopeError, match="not within any authorized range"):
        resolve_target("evil.example.com", home_cfg, resolver=lambda host: ["93.184.216.34"])


def test_hostname_with_any_resolved_ip_out_of_scope_is_blocked(home_cfg):
    # Even if one of two resolved IPs is in scope, the other being out of scope blocks the whole target.
    with pytest.raises(ScopeError, match="not within any authorized range"):
        resolve_target(
            "dualstack.lan", home_cfg, resolver=lambda host: ["192.168.1.50", "8.8.8.8"]
        )


def test_hostname_resolution_failure_is_rejected(home_cfg):
    def _raise(_host):
        raise ScopeError("simulated DNS failure")

    with pytest.raises(ScopeError, match="simulated DNS failure"):
        resolve_target("doesnotresolve.lan", home_cfg, resolver=_raise)


@pytest.mark.parametrize(
    "raw",
    [
        "192.168.1.10;rm -rf /",
        "192.168.1.10|whoami",
        "192.168.1.10 && id",
        "$(whoami)",
        "`whoami`",
        "192.168.1.10\nwhoami",
        "192.168.1.10 extra",
        "-oN /tmp/x",
        "--script=evil",
        "192.168.1.1-50",
        "../../../etc/passwd",
        "192.168.1.1,192.168.1.2",
    ],
)
def test_injection_attempts_are_rejected(home_cfg, raw):
    with pytest.raises(ScopeError):
        resolve_target(raw, home_cfg)


def test_invalid_syntax_is_rejected(home_cfg):
    with pytest.raises(ScopeError, match="not a valid IP, CIDR, or hostname"):
        resolve_target("not_a_valid_target!!", home_cfg)


def test_ipv6_allowed_when_in_scope():
    from nmap_mcp.config import Config

    cfg = Config(allowed_targets=("2001:db8::/64",), max_hosts=1000)
    resolved = resolve_target("2001:db8::1", cfg)
    assert resolved.nmap_targets == ("2001:db8::1",)

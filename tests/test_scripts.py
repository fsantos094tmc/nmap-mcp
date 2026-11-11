from __future__ import annotations

import pytest

from nmap_mcp.runner import PROTOCOL_SCRIPTS
from nmap_mcp.scripts import (
    ScriptError,
    assert_hardcoded_scripts_allowed,
    parse_script_db,
    resolve_protocol_scripts,
    resolve_scripts,
)


def test_parse_script_db_extracts_categories(catalog):
    assert catalog.categories_by_script["ssl-cert"] == {"default", "safe"}
    assert catalog.categories_by_script["smb-brute"] == {"brute", "intrusive"}


def test_concrete_safe_script_is_allowed(catalog):
    assert resolve_scripts("ssl-cert", catalog, include_intrusive=False) == ("ssl-cert",)


@pytest.mark.parametrize(
    "token",
    ["brute", "dos", "exploit", "intrusive", "smb-brute", "ftp-brute", "fuzzer", "malware"],
)
def test_dangerous_categories_and_scripts_are_rejected(catalog, token):
    with pytest.raises(ScriptError):
        resolve_scripts(token, catalog, include_intrusive=False)


def test_vuln_category_rejected_when_intrusive_off(catalog):
    with pytest.raises(ScriptError, match="no allowed scripts"):
        resolve_scripts("vuln", catalog, include_intrusive=False)


def test_vuln_category_expands_when_intrusive_on_minus_dos_exploit_brute(catalog):
    resolved = resolve_scripts("vuln", catalog, include_intrusive=True)
    assert "vulners" in resolved
    assert "http-vuln-cve2021-41773" in resolved
    assert "http-csrf" in resolved
    # smb-vuln-ms17-010 is tagged vuln+dos: dos is always blocked, even with intrusive on.
    assert "smb-vuln-ms17-010" not in resolved
    assert "smb-brute" not in resolved


def test_wildcard_tokens_are_rejected(catalog):
    with pytest.raises(ScriptError, match="not a valid script/category name"):
        resolve_scripts("http-*", catalog, include_intrusive=False)


def test_unknown_script_is_rejected(catalog):
    with pytest.raises(ScriptError, match="Unknown script or category"):
        resolve_scripts("totally-made-up-script", catalog, include_intrusive=False)


def test_comma_separated_requests_expand_each_token(catalog):
    resolved = resolve_scripts("ssl-cert,ssh-hostkey", catalog, include_intrusive=False)
    assert set(resolved) == {"ssl-cert", "ssh-hostkey"}


def test_safe_vuln_subset(catalog):
    safe_vuln = catalog.safe_vuln()
    assert "vulners" in safe_vuln
    assert "http-vuln-cve2021-41773" in safe_vuln
    assert "http-csrf" not in safe_vuln  # intrusive, not safe
    assert "smb-vuln-ms17-010" not in safe_vuln  # dos-tagged, always blocked


def test_hardcoded_protocol_scripts_are_all_allowed(catalog):
    required_only = {name: req for name, (req, _opt) in PROTOCOL_SCRIPTS.items()}
    assert_hardcoded_scripts_allowed(catalog, required_only)  # must not raise


def test_resolve_protocol_scripts_drops_missing_optional(catalog):
    effective = resolve_protocol_scripts(
        catalog, required=["ssl-cert"], optional=["http-security-headers", "nonexistent-script"]
    )
    assert "ssl-cert" in effective
    assert "http-security-headers" in effective
    assert "nonexistent-script" not in effective


def test_resolve_protocol_scripts_raises_on_missing_required(catalog):
    with pytest.raises(RuntimeError):
        resolve_protocol_scripts(catalog, required=["nonexistent-script"], optional=[])


def test_resolve_protocol_scripts_raises_on_blocked_required(catalog):
    with pytest.raises(RuntimeError):
        resolve_protocol_scripts(catalog, required=["smb-brute"], optional=[])

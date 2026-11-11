from __future__ import annotations

import pytest

from nmap_mcp.parser import ParserError, parse_nmap_xml
from tests.conftest import read_fixture


def test_empty_xml_text_returns_empty_result():
    result = parse_nmap_xml("")
    assert result.hosts == []


def test_empty_scan_fixture_has_no_hosts_but_run_stats():
    result = parse_nmap_xml(read_fixture("empty.xml"))
    assert result.hosts == []
    assert result.run_stats.hosts_total == 1
    assert result.run_stats.hosts_down == 1
    assert result.run_stats.exit_status == "success"


def test_host_down_fixture():
    result = parse_nmap_xml(read_fixture("host_down.xml"))
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.state == "down"
    assert host.ipv4 == "10.0.0.50"
    assert result.hosts_up == []


def test_multi_host_sweep_fixture():
    result = parse_nmap_xml(read_fixture("multi_host_sweep.xml"))
    assert len(result.hosts) == 3
    up = result.hosts_up
    assert len(up) == 2
    router = next(h for h in up if h.ipv4 == "192.168.1.1")
    assert router.mac == "AA:BB:CC:00:11:22"
    assert router.mac_vendor == "Netgear"
    assert router.hostnames == ["router.lan"]

    down = next(h for h in result.hosts if h.state == "down")
    assert down.ipv4 == "192.168.1.99"


def test_service_version_cpe_fixture():
    result = parse_nmap_xml(read_fixture("service_version_cpe.xml"))
    host = result.hosts[0]
    assert host.hostnames == ["nas.lan"]
    open_ports = host.open_ports
    assert {p.port_id for p in open_ports} == {22, 80}

    ssh = next(p for p in host.ports if p.port_id == 22)
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "9.6"
    assert ssh.service.cpes == ["cpe:/a:openbsd:openssh:9.6"]

    http = next(p for p in host.ports if p.port_id == 80)
    assert http.service.cpes == ["cpe:/a:nginx:nginx:1.26.0", "cpe:/o:linux:linux_kernel"]

    closed = next(p for p in host.ports if p.port_id == 443)
    assert closed.state == "closed"


def test_os_detect_fixture():
    result = parse_nmap_xml(read_fixture("os_detect.xml"))
    host = result.hosts[0]
    assert len(host.os_matches) == 2
    top = host.os_matches[0]
    assert top.name == "Linux 6.1 - 6.8"
    assert top.accuracy == 95
    assert top.classes[0].osfamily == "Linux"
    assert host.uptime_seconds == 98765
    assert host.distance == 1


def test_script_output_with_nested_tables_fixture():
    result = parse_nmap_xml(read_fixture("script_output_tables.xml"))
    host = result.hosts[0]
    port = host.ports[0]
    assert port.port_id == 443

    cert_script = next(s for s in port.scripts if s.id == "ssl-cert")
    assert "commonName" in cert_script.tables[0].elements
    assert cert_script.tables[0].elements["commonName"] == "nas.lan"

    ciphers_script = next(s for s in port.scripts if s.id == "ssl-enum-ciphers")
    tls_table = ciphers_script.tables[0]
    assert tls_table.key == "TLSv1.2"
    nested_cipher_table = tls_table.tables[0].tables[0]
    assert nested_cipher_table.elements["name"] == "TLS_AES_256_GCM_SHA384"

    host_script = host.scripts[0]
    assert host_script.id == "smb-os-discovery"
    assert "Windows Server 2022" in host_script.output


def test_malformed_xml_raises_parser_error():
    with pytest.raises(ParserError):
        parse_nmap_xml("<nmaprun><host>not closed")

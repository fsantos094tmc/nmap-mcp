from __future__ import annotations

from pathlib import Path

import pytest

from nmap_mcp.config import Config
from nmap_mcp.scripts import ScriptCatalog, parse_script_db

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


@pytest.fixture
def home_cfg() -> Config:
    """A config authorized for a typical home LAN, with one deny carve-out."""

    return Config(
        allowed_targets=("192.168.1.0/24", "10.10.0.0/24", "203.0.113.5"),
        deny_targets=("192.168.1.1/32",),
        max_hosts=256,
        timeout=600,
        max_parallel=2,
        max_timing=4,
        allow_intrusive=False,
        history_db=Path("/tmp/does-not-matter/history.db"),
        max_output_chars=20000,
    )


@pytest.fixture
def empty_scope_cfg() -> Config:
    return Config()


@pytest.fixture
def catalog() -> ScriptCatalog:
    text = read_fixture("script_db_sample.txt")
    return ScriptCatalog(categories_by_script=parse_script_db(text))

"""Environment-driven configuration, parsed once and frozen.

Every other module reads settings through :func:`get_config` rather than
touching ``os.environ`` directly, so behavior stays consistent for the
lifetime of the process and easy to override in tests.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Mapping

#: Hard ceiling on -T timing template, independent of what the operator sets.
ABSOLUTE_MAX_TIMING = 4


def _split_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise ValueError(f"{name}={raw!r} is not a valid integer") from None


def _bool_env(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    allowed_targets: tuple[str, ...] = field(default_factory=tuple)
    deny_targets: tuple[str, ...] = field(default_factory=tuple)
    max_hosts: int = 256
    timeout: int = 600
    max_parallel: int = 2
    max_timing: int = ABSOLUTE_MAX_TIMING
    allow_intrusive: bool = False
    history_db: Path = Path("/data/history.db")
    max_output_chars: int = 20000

    @property
    def scope_configured(self) -> bool:
        return len(self.allowed_targets) > 0


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Build a :class:`Config` from environment variables.

    ``env`` defaults to ``os.environ`` and is only overridden in tests.
    """

    source = env if env is not None else os.environ

    max_timing = _int_env(source, "NMAP_MAX_TIMING", ABSOLUTE_MAX_TIMING)
    max_timing = min(max_timing, ABSOLUTE_MAX_TIMING)
    if max_timing < 0:
        max_timing = 0

    return Config(
        allowed_targets=_split_csv(source.get("NMAP_ALLOWED_TARGETS", "")),
        deny_targets=_split_csv(source.get("NMAP_DENY_TARGETS", "")),
        max_hosts=_int_env(source, "NMAP_MAX_HOSTS", 256),
        timeout=_int_env(source, "NMAP_TIMEOUT", 600),
        max_parallel=_int_env(source, "NMAP_MAX_PARALLEL", 2),
        max_timing=max_timing,
        allow_intrusive=_bool_env(source, "NMAP_ALLOW_INTRUSIVE", False),
        history_db=Path(source.get("NMAP_HISTORY_DB", "/data/history.db")),
        max_output_chars=_int_env(source, "NMAP_MAX_OUTPUT_CHARS", 20000),
    )


@lru_cache(maxsize=1)
def get_config() -> Config:
    return load_config()


def reset_config_cache() -> None:
    """Clear the cached singleton. Tests call this after mutating env vars."""

    get_config.cache_clear()


def log_effective_config(cfg: Config | None = None) -> None:
    """Log the effective, non-secret configuration to stderr at startup."""

    cfg = cfg or get_config()
    print(
        "nmap-mcp config: "
        f"allowed_targets={list(cfg.allowed_targets)} "
        f"deny_targets={list(cfg.deny_targets)} "
        f"max_hosts={cfg.max_hosts} timeout={cfg.timeout}s "
        f"max_parallel={cfg.max_parallel} max_timing=T{cfg.max_timing} "
        f"allow_intrusive={cfg.allow_intrusive} "
        f"history_db={cfg.history_db} max_output_chars={cfg.max_output_chars}",
        file=sys.stderr,
    )

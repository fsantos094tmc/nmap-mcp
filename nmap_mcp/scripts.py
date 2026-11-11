"""NSE script allowlist, derived from nmap's own script.db.

The AI never sends ``--script`` content straight through. Every requested
script or category name is resolved against a catalog parsed from
``script.db`` and expanded into concrete, individually-vetted script names
before it reaches argv. This is what keeps a category like "vuln" from
silently including something destructive if nmap's own categorization
changes between versions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SCRIPT_DB_PATH = Path("/usr/share/nmap/scripts/script.db")

#: These categories are never runnable through this server, regardless of config.
ALWAYS_BLOCKED_CATEGORIES = frozenset({"dos", "exploit", "brute", "malware", "fuzzer"})

#: Categories that make a script eligible by default (NMAP_ALLOW_INTRUSIVE=0).
DEFAULT_ELIGIBLE_CATEGORIES = frozenset({"safe", "default"})

#: Categories additionally eligible when intrusive mode is on, for vuln_scan only.
INTRUSIVE_ELIGIBLE_CATEGORIES = frozenset({"vuln", "intrusive"})

_ENTRY_RE = re.compile(
    r'Entry\s*\{\s*filename\s*=\s*"([^"]+)"\s*,\s*categories\s*=\s*\{([^}]*)\}\s*,?\s*\}'
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ScriptError(ValueError):
    """A requested script or category could not be resolved or is not allowed."""


@dataclass(frozen=True)
class ScriptCatalog:
    categories_by_script: dict[str, frozenset[str]]

    def is_blocked(self, script_name: str) -> bool:
        cats = self.categories_by_script.get(script_name, frozenset())
        return bool(cats & ALWAYS_BLOCKED_CATEGORIES)

    def allowed_default(self) -> frozenset[str]:
        # vuln/intrusive scripts are gated separately (see allowed_intrusive/safe_vuln):
        # vuln_scan is the only sanctioned path to them, so they're excluded here even
        # if nmap also tags them safe/default.
        excluded = ALWAYS_BLOCKED_CATEGORIES | INTRUSIVE_ELIGIBLE_CATEGORIES
        return frozenset(
            name
            for name, cats in self.categories_by_script.items()
            if (cats & DEFAULT_ELIGIBLE_CATEGORIES) and not (cats & excluded)
        )

    def allowed_intrusive(self) -> frozenset[str]:
        return frozenset(
            name
            for name, cats in self.categories_by_script.items()
            if (cats & INTRUSIVE_ELIGIBLE_CATEGORIES) and not (cats & ALWAYS_BLOCKED_CATEGORIES)
        )

    def safe_vuln(self) -> frozenset[str]:
        """vuln scripts that are *also* tagged safe: vuln_scan's non-intrusive mode."""

        return frozenset(
            name
            for name, cats in self.categories_by_script.items()
            if "vuln" in cats and "safe" in cats and not (cats & ALWAYS_BLOCKED_CATEGORIES)
        )

    def category_index(self) -> dict[str, frozenset[str]]:
        index: dict[str, set[str]] = {}
        for name, cats in self.categories_by_script.items():
            for cat in cats:
                index.setdefault(cat.lower(), set()).add(name)
        return {cat: frozenset(names) for cat, names in index.items()}


def parse_script_db(text: str) -> dict[str, frozenset[str]]:
    """Parse the contents of nmap's script.db into {script_name: categories}."""

    result: dict[str, frozenset[str]] = {}
    for match in _ENTRY_RE.finditer(text):
        filename, categories_blob = match.groups()
        name = filename[:-4] if filename.endswith(".nse") else filename
        categories = frozenset(re.findall(r'"([^"]*)"', categories_blob))
        result[name] = categories
    return result


def load_catalog(path: Path = DEFAULT_SCRIPT_DB_PATH) -> ScriptCatalog:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    categories_by_script = parse_script_db(text)
    if not categories_by_script:
        raise RuntimeError(
            f"Parsed zero scripts from {path}; nmap's script.db format may have changed."
        )
    return ScriptCatalog(categories_by_script=categories_by_script)


def allowed_scripts(catalog: ScriptCatalog, *, include_intrusive: bool) -> frozenset[str]:
    allowed = set(catalog.allowed_default())
    if include_intrusive:
        allowed |= catalog.allowed_intrusive()
    return frozenset(allowed)


def _split_requested(requested: str) -> list[str]:
    tokens = [t.strip() for t in requested.split(",") if t.strip()]
    if not tokens:
        raise ScriptError("No scripts or categories were specified.")
    return tokens


def resolve_scripts(
    requested: str, catalog: ScriptCatalog, *, include_intrusive: bool
) -> tuple[str, ...]:
    """Expand a comma-separated request of script/category names to concrete,
    individually-allowed script names. Never returns a category or wildcard."""

    allowed = allowed_scripts(catalog, include_intrusive=include_intrusive)
    categories = catalog.category_index()
    resolved: set[str] = set()

    for token in _split_requested(requested):
        if not _TOKEN_RE.match(token):
            raise ScriptError(f"{token!r} is not a valid script/category name (no wildcards).")

        lname = token.lower()
        if token in catalog.categories_by_script:
            if token not in allowed:
                raise ScriptError(f"Script {token!r} is blocked or not in the allowed set.")
            resolved.add(token)
        elif lname in catalog.categories_by_script:
            if lname not in allowed:
                raise ScriptError(f"Script {token!r} is blocked or not in the allowed set.")
            resolved.add(lname)
        elif lname in categories:
            members = categories[lname] & allowed
            if not members:
                raise ScriptError(
                    f"Category {token!r} has no allowed scripts "
                    "(blocked category, or NMAP_ALLOW_INTRUSIVE is off)."
                )
            resolved |= members
        else:
            raise ScriptError(f"Unknown script or category: {token!r}")

    return tuple(sorted(resolved))


def resolve_protocol_scripts(
    catalog: ScriptCatalog,
    required: list[str],
    optional: list[str] = (),
) -> list[str]:
    """Build the effective script list for a hardcoded protocol tool.

    ``required`` scripts must exist in this nmap's script.db and be allowed,
    or this raises RuntimeError (fail loudly at startup). ``optional``
    scripts (not every nmap version ships every script) are included only
    if present and allowed, otherwise silently dropped."""

    allowed = allowed_scripts(catalog, include_intrusive=False)
    missing = [s for s in required if s not in catalog.categories_by_script]
    blocked = [s for s in required if s in catalog.categories_by_script and s not in allowed]
    if missing or blocked:
        problems = [f"{s!r} unknown to this nmap install" for s in missing]
        problems += [
            f"{s!r} not allowed (categories={sorted(catalog.categories_by_script[s])})"
            for s in blocked
        ]
        raise RuntimeError("Required protocol scripts unavailable: " + "; ".join(problems))

    effective = list(required)
    for script in optional:
        if script in allowed:
            effective.append(script)
    return effective


def assert_hardcoded_scripts_allowed(
    catalog: ScriptCatalog, tool_scripts: dict[str, list[str]]
) -> None:
    """Startup assertion: every script a protocol tool hardcodes must still be
    in the default-allowed set per the *currently installed* nmap's script.db.
    Raises RuntimeError (fail loudly) on any mismatch."""

    allowed = allowed_scripts(catalog, include_intrusive=False)
    problems: list[str] = []
    for tool_name, scripts in tool_scripts.items():
        for script in scripts:
            if script not in catalog.categories_by_script:
                problems.append(f"{tool_name}: script {script!r} is unknown to this nmap install")
            elif script not in allowed:
                cats = sorted(catalog.categories_by_script[script])
                problems.append(f"{tool_name}: script {script!r} is not allowed (categories={cats})")
    if problems:
        raise RuntimeError(
            "Hardcoded protocol-tool scripts disagree with nmap's script.db:\n  "
            + "\n  ".join(problems)
        )

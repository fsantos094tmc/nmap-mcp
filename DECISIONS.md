# Decisions

Judgment calls made while building this where the requirements were ambiguous or
silent, and why.

## `mcp` pinned to `<2`
The installed `mcp` package defaulted to 2.x, which renamed `FastMCP` to
`MCPServer` and changed its API. The project conventions (`@mcp.tool()`, no `prompt=` on the constructor) are written against
`FastMCP` v1. Pinned `mcp[cli]>=1.2.0,<2` so `from mcp.server.fastmcp import
FastMCP` keeps working. Revisit if a future task needs v2-only features.

## XML parsing: stdlib `ElementTree`, not `defusedxml`
Either would work. The XML being parsed is nmap's own `-oX -` output
from a subprocess we invoke ourselves with a fixed, non-file-reading argv —
there's no untrusted XML entering the parser, so the extra dependency
wasn't worth adding. If a future tool ever parses XML from an external
source, switch that path to `defusedxml`.

## `vuln`/`intrusive` scripts are excluded from the *general* allowlist, even if also tagged `safe`
The design says intrusive mode "additionally allow[s] vuln and intrusive
scripts, only in vuln_scan." Taken literally, a script tagged both `vuln`
and `safe` (e.g. `vulners`) would otherwise slip into `allowed_default()`
and become reachable from `script_scan`/`host_summary` even with
`NMAP_ALLOW_INTRUSIVE=0`. `scripts.ScriptCatalog.allowed_default()` now
excludes anything tagged `vuln` or `intrusive` unconditionally; the only
ways to reach those scripts are `vuln_scan`'s `safe_vuln()` (always) and
`allowed_intrusive()` (only when `NMAP_ALLOW_INTRUSIVE=1`).

## `host_summary`'s "default scripts" are expanded to concrete names, not passed as the bare category `default`
The rule "never pass a category... directly" is written about AI-supplied
script requests, but applying it uniformly keeps every single script
invocation — hardcoded or not — auditable against the same allowlist
machinery. `host_summary` resolves `catalog.allowed_default()` to a
concrete comma list at call time.

## Fixed internal timing flag on every builder
The tool table only shows `-T4` explicitly for `quick_scan`/some
protocol scans. Every `build_*_argv` function in `runner.py` applies
`timing_flag(cfg, requested=4)` (capped at `NMAP_MAX_TIMING`) for
predictable scan duration under `NMAP_TIMEOUT`, even for tools the table
didn't show a `-T` for (`os_detect`, the protocol audits). This is an
internal default, never AI-controlled, so it doesn't conflict with "no raw
flags from the AI."

## `dns_audit` scans UDP/53
DNS predominantly runs over UDP; `dns-recursion`/`dns-nsid` need port 53
reachable to produce output. Fixed as `-sU -p 53`, no override.

## Protocol-audit tools without a `ports` param use fixed defaults
By design, `smb_audit`, `rdp_audit`, `dns_audit`, and
`database_audit` take no `ports` argument. Fixed ports:
`smb_audit`=139,445 · `rdp_audit`=3389 · `dns_audit`=53 ·
`database_audit`=1433,3306,6379,27017 (MSSQL, MySQL, Redis, MongoDB).

## Process kill is platform-specific
POSIX: spawn with `os.setsid` (new process group), kill via
`os.killpg(pgid, SIGKILL)` so a child nmap ever spawns dies too. Windows:
`taskkill /T /F /PID <pid>`, which kills the whole process tree by PID
lineage instead. Exercised by
`test_runner.py::test_runner_timeout_kills_process_and_returns_partial_output`
on whichever OS the suite runs on — this dev machine is Windows, so that's
the path actually tested here; the POSIX path will run for real inside the
Linux container.

## Container image status
The `Dockerfile` and `scripts/test_container.py` (`make test-container`) were written on a machine without Docker; the unit suite was run natively on Windows. Run `make test-container` to verify the image on your machine.

## Scope left unconfigured
`NMAP_ALLOWED_TARGETS` ships unset (fail closed).
Every scan tool correctly refuses with a clear message until it's set;
`get_scope()`, `list_scans()`, `get_scan()`, and the diff tools work
regardless, since they don't scan anything.

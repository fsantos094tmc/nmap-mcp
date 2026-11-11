# nmap-mcp

[![CI](https://github.com/fsantos094tmc/nmap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/fsantos094tmc/nmap-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

A scoped [MCP](https://modelcontextprotocol.io) server that lets an AI assistant run `nmap`
scans — but only against networks you are authorized to test, using a fixed,
non-extensible set of tools instead of raw nmap flags.

> ## ⚠️ Authorization notice
> Only scan networks and hosts you **own** or have **explicit written
> authorization** to test. Unauthorized scanning of third-party networks may
> violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act
> (UK), or equivalent laws elsewhere, and may violate your ISP's or
> employer's acceptable-use policy. This server enforces a scope allowlist
> (`NMAP_ALLOWED_TARGETS`) as a technical safeguard, but **you** are
> responsible for having authorization before you set it.

## Why this exists

An AI assistant with unrestricted `nmap` access is a liability: it could be
steered (by a prompt injection, a typo, or its own mistake) into scanning a
network you don't own, writing files outside the sandbox, or running an
intrusive/exploit script. This server closes those doors structurally:

- The AI never supplies raw nmap flags — every tool builds its own fixed
  argv from validated scalar parameters.
- Every target is checked against an allowlist (and an optional deny-list
  carve-out) before anything runs; hostnames are resolved and pinned to
  their IP so DNS can't move the target after the check.
- Every NSE script or category is resolved against an allowlist derived
  from nmap's own `script.db`, so `dos`/`exploit`/`brute`/`malware`/`fuzzer`
  scripts can never run, and `vuln`/`intrusive` scripts only run (in
  `vuln_scan`) if you explicitly opt in.
- No output-file flags, no evasion flags (decoys, spoofing, fragmentation,
  proxies), no `-T5`.
- The container runs as a non-root user with just the capabilities nmap
  needs (`cap_net_raw`, `cap_net_admin`) — not root.

## Architecture

```
                 ┌─────────────────────────┐
  AI assistant   │        server.py        │   thin MCP tool layer;
  (Claude, etc.) │  (FastMCP tool defs)     │   no validation/nmap logic
      │          └───────────┬──────────────┘
      │ stdio/MCP            │ calls into
      ▼                      ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐
│ scope.py │  │scripts.py│  │runner.py │  │ parser.py │  │history.py│
│ allowlist│  │ NSE      │  │ argv     │  │ nmap XML  │  │ SQLite   │
│ + DNS    │  │ allowlist│  │ templates│  │  -> typed │  │ history  │
│ pinning  │  │from      │  │ + sandbox│  │  models   │  │ + diff   │
│          │  │script.db │  │ subprocess│  │           │  │          │
└──────────┘  └──────────┘  └────┬─────┘  └───────────┘  └──────────┘
                                  │ asyncio.create_subprocess_exec
                                  ▼
                            ┌──────────┐
                            │   nmap   │
                            └──────────┘
```

`server.py` never talks to `nmap` directly. `runner.py` is the only module
that invokes a subprocess, always via `create_subprocess_exec` (never a
shell), always with `-oX -`, always under a hard timeout.

## Tools

| Tool | What it does |
|---|---|
| `get_scope()` | Show configured scope, limits, and whether intrusive scripts are enabled |
| `discover_hosts(target)` | Ping-sweep (`-sn`) to find live hosts |
| `quick_scan(target, top_ports=100)` | Scan the N most common TCP ports |
| `port_scan(target, ports, scan_type="syn")` | SYN / connect / UDP scan of specific ports |
| `service_scan(target, ports="", intensity=7)` | Service/version detection |
| `os_detect(target)` | OS fingerprinting |
| `script_scan(target, scripts, ports="")` | Run allowlisted NSE scripts/categories |
| `network_inventory(target)` | Two-phase sweep + service scan of live hosts |
| `host_summary(target)` | OS + ports + versions + default scripts, as a report |
| `ssl_audit(target, ports="443")` | Certificate, cipher suites, clock skew |
| `http_audit(target, ports="80,443")` | Title, headers, server banner, methods, robots.txt |
| `ssh_audit(target, ports="22")` | Algorithm support, host key fingerprints |
| `smb_audit(target)` | SMB protocol versions, security mode |
| `rdp_audit(target)` | RDP encryption level, NTLM info |
| `dns_audit(target)` | Open recursion, NSID (no zone transfer/brute unless intrusive) |
| `database_audit(target)` | Exposed MySQL/MSSQL/MongoDB/Redis info (no brute) |
| `vuln_scan(target, ports="")` | `vuln`+`safe` scripts, or full `vuln` category if intrusive mode is on |
| `list_scans(limit=20, target="")` | Recent scan history |
| `get_scan(scan_id)` | Full stored result for one scan |
| `diff_scans(scan_id_a, scan_id_b)` | Diff two scans: hosts/ports/OS changes |
| `diff_latest(target)` | Diff the two most recent scans of a target |

## Configuration (environment variables)

| Var | Default | Purpose |
|---|---|---|
| `NMAP_ALLOWED_TARGETS` | *(empty → refuse all scans)* | Comma-separated CIDRs/IPs you're authorized to scan |
| `NMAP_DENY_TARGETS` | *(empty)* | CIDRs/IPs carved out of the allowlist |
| `NMAP_MAX_HOSTS` | `256` | Max addresses per scan |
| `NMAP_TIMEOUT` | `600` | Hard kill, seconds, per scan |
| `NMAP_MAX_PARALLEL` | `2` | Concurrent scans |
| `NMAP_MAX_TIMING` | `4` | Highest allowed `-T` (never above 4) |
| `NMAP_ALLOW_INTRUSIVE` | `0` | `1` enables `vuln`/`intrusive` scripts, only in `vuln_scan` |
| `NMAP_HISTORY_DB` | `/data/history.db` | SQLite history file (mount a volume over it) |
| `NMAP_MAX_OUTPUT_CHARS` | `20000` | Truncate tool output beyond this |

The effective config is logged to stderr at startup.

## Install (Docker; Windows 11 + WSL2 walkthrough)

**0. Prerequisites — Docker (on Windows: WSL2 and Docker Desktop).** Install both first:

```powershell
wsl --install              # installs a default Linux distro + WSL2 kernel
# reboot if prompted, then open the new Linux distro once to finish setup
```

Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/),
and in **Settings → General** confirm "Use the WSL 2 based engine" is
checked, and in **Settings → Resources → WSL Integration** enable
integration with your distro. Verify from a Windows terminal:

```powershell
wsl -l -v        # your distro should show VERSION 2
docker version   # should succeed, not "command not found"
```

**1. Build the image** (from this project directory, in PowerShell or WSL):

```powershell
docker build -t nmap-mcp .
```

**2. Create the history volume** (persists `history.db` across container restarts):

```powershell
docker volume create nmap-mcp-data
```

**3. Decide your authorized ranges.** `NMAP_ALLOWED_TARGETS` is empty by
default, and every scan tool refuses with a clear error until you set it.
Pick the CIDR(s)/IP(s) you own or are explicitly authorized to test, e.g.
`192.168.1.0/24`.

**4. Claude Code:**

```bash
claude mcp add nmap -- docker run -i --rm --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v nmap-mcp-data:/data \
  -e NMAP_ALLOWED_TARGETS=<your-authorized-ranges> \
  nmap-mcp
```

**5. Claude Desktop** — add to `claude_desktop_config.json`
(`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "nmap": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--network", "host",
        "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
        "-v", "nmap-mcp-data:/data",
        "-e", "NMAP_ALLOWED_TARGETS=<your-authorized-ranges>",
        "nmap-mcp"
      ]
    }
  }
}
```

**6. Optional: Docker MCP Toolkit gateway catalog entry.** Honest answer:
**use the direct method above instead.** The Toolkit gateway's
`custom.yaml`/`registry.yaml` catalog format doesn't have a way to express
`--cap-add NET_RAW`, `--cap-add NET_ADMIN`, or `--network host` on the
container it launches — without raw-socket capabilities nmap falls back to
slow, less-accurate connect-scan-only behavior, and without host
networking on Linux you'd only see the container's own virtual network.
If you want to try it anyway, the catalog entry would look like:

```yaml
# custom.yaml
registry:
  nmap:
    description: Scoped nmap scanning, restricted to authorized targets
    title: nmap-mcp
    image: nmap-mcp:latest
    dateAdded: "2026-11-07T00:00:00Z"
    tools:
      - get_scope
      - discover_hosts
      - quick_scan
      - port_scan
      - service_scan
      - os_detect
      - script_scan
      - network_inventory
      - host_summary
      - ssl_audit
      - http_audit
      - ssh_audit
      - smb_audit
      - rdp_audit
      - dns_audit
      - database_audit
      - vuln_scan
      - list_scans
      - get_scan
      - diff_scans
      - diff_latest
```
but expect degraded scan capability versus the direct `docker run` method.

**7. Networking caveat on Docker Desktop (WSL2 backend).** `--network host`
is accepted but behaves differently than on native Linux: Docker Desktop's
WSL2 VM sits between the container and your real LAN, so:
- **Works well:** TCP connect scans (`port_scan scan_type=connect`),
  service/version detection, OS/protocol audits against targets you can
  already reach by IP.
- **May not work or may be inaccurate:** ARP-based host discovery
  (`discover_hosts` may need to fall back to ICMP/TCP probing), raw SYN
  scans and OS fingerprinting (`-sS`, `-O`) depending on Docker Desktop
  version and WSL2 kernel capabilities.
- **Fallback:** if LAN visibility is unreliable through Docker Desktop, run
  the server natively instead: `uv sync && uv run nmap-mcp` directly inside
  your WSL2 distro (with real `nmap` installed there via `sudo apt install
  nmap`), which has an unvirtualized view of the network. You lose the
  container's non-root/capability sandboxing in exchange for full nmap
  fidelity — a reasonable trade for a machine you control.

## Example prompts

1. "What's my scan scope?"
2. "Discover live hosts on my LAN."
3. "Run a quick scan on 192.168.1.10 and tell me what's open."
4. "Give me a host summary for my router."
5. "Diff the last two scans of 192.168.1.10 — what changed?"

## Development

```bash
uv sync
uv run pytest -m "not live"
```

See [CLAUDE.md](CLAUDE.md) for the safety invariants any change must keep,
[DECISIONS.md](DECISIONS.md) for design rationale, and
[CONTRIBUTING.md](CONTRIBUTING.md) / [SECURITY.md](SECURITY.md).

Live tests (opt-in, require a real `nmap` binary and loopback access):

```bash
uv run pytest -m live
```

## License

[MIT](LICENSE)

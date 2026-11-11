# Security policy

nmap-mcp's purpose is to keep an AI from scanning targets it isn't authorized
to scan or running destructive scripts. Anything that defeats that is a
security bug. Examples:

- A way to make a tool scan a target outside `NMAP_ALLOWED_TARGETS` (or inside `NMAP_DENY_TARGETS`)
- A way to inject a raw nmap flag, or write a file via nmap
- A way to run a blocked NSE script (`dos`, `exploit`, `brute`, `malware`, `fuzzer`) or reach `vuln`/`intrusive` scripts outside `vuln_scan` / without `NMAP_ALLOW_INTRUSIVE=1`
- A scope check that fails open

## Reporting

Please report privately via GitHub's
[private vulnerability reporting](https://github.com/fsantos094tmc/nmap-mcp/security/advisories/new)
rather than a public issue. You should get a response within a few days.

## Usage

Only scan systems you own or have written permission to test. You are
responsible for the value you set in `NMAP_ALLOWED_TARGETS`.

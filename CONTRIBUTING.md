# Contributing

Thanks for helping. This project is deliberately restrictive; please read
[CLAUDE.md](CLAUDE.md) first. Its safety rules are the contract, and PRs that
relax them (raw flags, unscoped targets, unblocking script categories, shell
execution) will not be merged.

## Workflow

```bash
uv sync
uv run pytest -m "not live"
```

- New scan tool: add a `build_*_argv` function in `runner.py`, route the target through `scope.resolve_target()` and scripts through `scripts.resolve_*`, keep `server.py` thin, and add the builder to `BUILDERS` in `tests/test_runner.py`.
- Live tests (`-m live`) need a real `nmap` and are opt-in.
- Keep logs on stderr; stdout is MCP traffic.

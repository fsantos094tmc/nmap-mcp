# Rules for editing nmap-mcp

This server exists to let an AI run `nmap` without being able to scan
something it isn't authorized to, or run something destructive. Every rule
below exists to close a specific hole. If you're changing code here, keep
these invariants — don't relax them to make a feature easier to add.

## Safety rules (non-negotiable)

1. **The AI never supplies a raw nmap flag.** Every tool in `server.py`
   calls a `build_*_argv` function in `runner.py` that takes validated
   scalar parameters and returns a fixed argv shape. If you're adding a
   tool, add a builder function — don't let a tool string-format flags
   itself, and don't add a parameter that gets passed through to argv
   unvalidated.
2. **Every scan tool resolves its target through `scope.resolve_target()`
   first**, and nothing else may add a tool that reaches `runner.NmapRunner`
   without having gone through it. Hostnames must be resolved and pinned to
   IP(s) before they reach argv — never pass a hostname string to nmap.
3. **Every NSE script/category request goes through `scripts.resolve_scripts()`
   or `scripts.resolve_protocol_scripts()`.** Never pass a bare category,
   wildcard, or raw user string to `--script`. `dos`, `exploit`, `brute`,
   `malware`, `fuzzer` are blocked unconditionally in `scripts.py` — don't
   add a config flag that lifts that.
4. **`vuln`/`intrusive` scripts are reachable only through `vuln_scan`**,
   and only when `NMAP_ALLOW_INTRUSIVE=1`. Don't let `allowed_default()`
   (used by `script_scan`/`host_summary`) include them, even if a script is
   also tagged `safe` — see DECISIONS.md.
5. **No output-file flags** (`-oN/-oG/-oA`, or `-oX` to anything but `-`),
   no `--script-args-file`, `--datadir`, `--resume`, `-iL`, `--excludefile`.
   No evasion flags (`-D`, `-S`, `-e`, `--spoof-mac`, `--proxies`, `-b`,
   `-sI`, `-f`/`--mtu`, `--badsum`, `--data-length`). No `-T5`/`-T6`. These
   are enforced by `runner.FORBIDDEN_TOKENS` + `assert_no_forbidden_flags()`
   — if you add a builder, its output must still pass that assertion (the
   test suite checks this for every builder).
6. **Subprocesses only via `asyncio.create_subprocess_exec`, never a
   shell.** No `shell=True`, no string-joined commands.
7. **Every scan runs under a hard timeout** (`NMAP_TIMEOUT` via
   `asyncio.wait_for`, plus `--host-timeout` on the nmap side) **and
   through the semaphore** (`NMAP_MAX_PARALLEL`). Don't call nmap directly
   from a tool function — always through `NmapRunner.run()`.
8. **Fail closed.** An empty `NMAP_ALLOWED_TARGETS` must refuse every scan
   tool with a clear message. Any ambiguous parse/resolve/validation
   failure raises, it doesn't default to "allow."
9. **Logs go to stderr only.** stdout is MCP JSON-RPC traffic — never
   `print()` to stdout, and don't let nmap's own stdout mix with anything
   but the XML we read via the pipe.

## Code rules

- `server.py` stays thin: no validation, no nmap flag logic, no scope/script
  resolution inline. It resolves target/scripts via the other modules,
  calls a `runner.build_*_argv` + `NmapRunner.run()`, formats via
  `format.py`, records via `history.py`, and returns a string.
- Every tool function: scalar params (`str`/`int`/`bool`) with defaults
  where the spec gives one, single-line docstring, no `@mcp.prompt()`.
- Every scan tool records its result in history and includes `scan_id` in
  its returned string.
- Output is capped by `NMAP_MAX_OUTPUT_CHARS` via `format.truncate()` —
  don't bypass it with an uncapped return.
- Run `uv run pytest -m "not live"` before calling anything done. New
  builder functions need a case added to `tests/test_runner.py`'s
  `BUILDERS` property test. New script categories or hardcoded protocol
  script lists need a startup assertion in `server._init()` via
  `scripts.resolve_protocol_scripts()`/`assert_hardcoded_scripts_allowed()`.

.PHONY: build test test-container

build:
	docker build -t nmap-mcp .

test:
	uv run pytest -m "not live"

test-container: build
	uv run python scripts/test_container.py nmap-mcp

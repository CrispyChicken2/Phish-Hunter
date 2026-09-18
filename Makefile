.PHONY: install lint format typecheck test check ct-up ct-down run replay

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy src tests

test:
	uv run pytest -q

check: lint typecheck test

ct-up:
	docker compose up -d certstream

ct-down:
	docker compose down

run:
	uv run lookalike-hunter ingest --source certstream

replay:
	uv run lookalike-hunter ingest --source replay --replay-path tests/fixtures/certstream_sample.jsonl

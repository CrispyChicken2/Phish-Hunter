.PHONY: install lint format typecheck test check ct-up ct-down run replay dashboard tf-fmt tf-validate tf-plan

install:
	uv sync --all-extras

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

# Review UI on http://localhost:8501 only; .streamlit/config.toml keeps it off the LAN.
dashboard:
	uv run --extra dashboard streamlit run src/lookalike_hunter/dashboard/app.py

# Terraform (infra/). tf-fmt and tf-validate need no AWS credentials. tf-plan does, and
# is run by the owner, never by CI.
tf-fmt:
	terraform -chdir=infra fmt -check -recursive

tf-validate:
	terraform -chdir=infra init -backend=false -input=false
	terraform -chdir=infra validate

tf-plan:
	terraform -chdir=infra plan -input=false

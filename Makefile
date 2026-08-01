.PHONY: sync run test lint typecheck fmt check

## Instala y resuelve dependencias
sync:
	uv sync

## Servidor de desarrollo (recarga automática)
run:
	uv run uvicorn role_radar.main:app --reload

## Tests
test:
	uv run pytest

## Lint (Ruff)
lint:
	uv run ruff check .

## Type check (mypy strict)
typecheck:
	uv run mypy .

## Formato (Ruff format + autofix de lint)
fmt:
	uv run ruff format .
	uv run ruff check --fix .

## Verificación completa: lint + typecheck + test
check: lint typecheck test

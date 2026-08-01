.PHONY: sync run migrate test lint typecheck fmt check seed-boards collect

## Instala y resuelve dependencias
sync:
	uv sync

## Servidor de desarrollo (recarga automática)
run:
	uv run uvicorn role_radar.main:app --reload

## Migraciones (Alembic)
migrate:
	uv run alembic upgrade head

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

## Semilla de boards Greenhouse curados
seed-boards:
	uv run role-radar seed-boards

## Ejecuta una colección manual en proceso
collect:
	uv run role-radar collect

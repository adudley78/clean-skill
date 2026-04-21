.PHONY: install test lint typecheck fmt sandbox clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

fmt:
	ruff format .
	ruff check --fix .

typecheck:
	mypy

sandbox:
	docker build -f docker/sandbox.Dockerfile -t cleanskill/sandbox:latest .

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov

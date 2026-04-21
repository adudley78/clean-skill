.PHONY: install test test-integration lint typecheck fmt check sandbox-build sandbox-test sandbox clean migrate migration worker scheduler dev

PYTHON ?= python

# On macOS, Docker Desktop ships the CLI inside the .app bundle (not on
# PATH) and exposes its daemon socket under ~/.docker/run/ unless the
# user opts into /var/run/docker.sock. Surfacing both here means
# `make sandbox-*` works on a stock Docker Desktop install without
# asking contributors to fiddle with PATH or DOCKER_HOST.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  DOCKER_MAC_BIN_DIR := /Applications/Docker.app/Contents/Resources/bin
  ifneq ($(wildcard $(DOCKER_MAC_BIN_DIR)/docker),)
    # Prepend Docker.app's bin to PATH so both `docker` and its credential
    # helpers (docker-credential-desktop, docker-compose, ...) resolve.
    DOCKER_ENV := PATH="$(DOCKER_MAC_BIN_DIR):$$PATH"
  endif
  DOCKER_MAC_SOCK := $(HOME)/.docker/run/docker.sock
  ifneq ($(wildcard $(DOCKER_MAC_SOCK)),)
    DOCKER_ENV += DOCKER_HOST=unix://$(DOCKER_MAC_SOCK)
  endif
endif

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	pytest -q

# Full dynamic integration: builds the sandbox image if missing, then
# runs the gVisor integration suite. Falls back to runc with a warning
# on hosts without gVisor (macOS Docker Desktop, unprivileged runners).
test-integration: sandbox-build
	$(DOCKER_ENV) \
	CLEAN_SKILL_RUN_INTEGRATION=1 \
	CLEAN_SKILL_SANDBOX_IMAGE=cleanskill/sandbox:latest \
	pytest -v -m integration tests/integration

lint:
	ruff check .

fmt:
	ruff format .
	ruff check --fix .

typecheck:
	mypy

check: lint typecheck test

sandbox-build:
	$(DOCKER_ENV) docker build -f docker/sandbox.Dockerfile -t cleanskill/sandbox:latest .

sandbox-test: test-integration

# Legacy alias — older docs refer to `make sandbox`.
sandbox: sandbox-build

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov

## Apply all pending Alembic migrations (requires CLEAN_SKILL_DB_URL).
migrate:
	alembic upgrade head

## Generate a new migration from model changes: make migration msg="your description"
migration:
	alembic revision --autogenerate -m "$(msg)"

## Run the RQ worker against CLEAN_SKILL_REDIS_URL.
worker:
	python -m clean_skill.worker.entrypoint

## Run the crawler scheduler.
scheduler:
	python -m clean_skill.crawler.scheduler

## Bring up the full dev stack (Redis + worker + scheduler) in docker compose.
dev:
	$(DOCKER_ENV) docker compose -f docker/docker-compose.dev.yml up --build

.DEFAULT_GOAL := help
PY ?= .venv/bin/python
UV ?= uv
PORT ?= 8080
IMAGE ?= airt:latest

.PHONY: help venv install dev run test lint style bump fmt node-test docker-build docker-run compose-up compose-down clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

venv:  ## Create .venv with uv (falls back to python -m venv)
	@test -d .venv || ($(UV) venv .venv --python 3.12 2>/dev/null || python3 -m venv .venv)

install: venv  ## Install the package (runtime deps only)
	$(UV) pip install --python $(PY) -e .

dev: venv  ## Install with dev, postgres and mitm extras
	$(UV) pip install --python $(PY) -e ".[dev,postgres,mitm]"

run:  ## Start the gateway (airt serve)
	$(PY) -m airt.cli serve --port $(PORT)

test:  ## Run the Python test suite
	$(PY) -m pytest -q

node-test:  ## Run the Node SDK self-test
	node sdk/node/test.js

lint:  ## Ruff check, format check (integrations, examples, scripts) and the style guard
	$(PY) -m ruff check airt tests examples scripts
	$(PY) -m ruff format --check airt/integrations examples
	$(PY) scripts/check_style.py

style:  ## Style guard only (em dashes, merge markers)
	$(PY) scripts/check_style.py

bump:  ## Bump the version everywhere: make bump VERSION=1.2.3 (DRY=1 to preview)
	@test -n "$(VERSION)" || (echo "usage: make bump VERSION=1.2.3 [DRY=1]" && exit 1)
	$(PY) scripts/bump_version.py $(if $(DRY),--dry-run,) $(VERSION)

fmt:  ## Ruff format and autofix
	$(PY) -m ruff format airt tests examples scripts
	$(PY) -m ruff check --fix airt tests examples scripts

docker-build:  ## Build the container image
	docker build -t $(IMAGE) .

docker-run: docker-build  ## Run the image with .env, data and logs mounted
	docker run --rm -it -p $(PORT):8080 --env-file .env -v airt-data:/app/data -v airt-logs:/app/logs $(IMAGE)

compose-up:  ## docker compose up (add PROFILE=postgres for PostgreSQL)
	docker compose $(if $(PROFILE),--profile $(PROFILE),) up -d --build

compose-down:  ## docker compose down
	docker compose --profile postgres down

clean:  ## Remove caches and build artefacts (keeps data/ and logs/)
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# nai-security release automation
#
#   make check     Verify .env PYPI_TOKEN against PyPI API (runs first)
#   make release   Interactive full release (API check first, then prompts)
#   make bump      Interactive version bump only
#   make test      Run pytest
#   make build     Build sdist/wheel + twine check
#   make publish   API check, then upload current version to PyPI
#   make version   Show current version
#   make wiki      Publish wiki/*.md to GitHub Wiki

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest

.PHONY: help check release test build publish version bump wiki ensure-venv

help:
	@echo "Targets:"
	@echo "  make check     Verify PYPI_TOKEN in .env against PyPI API"
	@echo "  make release   Interactive release (API check first, then version prompts)"
	@echo "  make bump      Interactive version bump only"
	@echo "  make test      Run full pytest suite"
	@echo "  make build     Build sdist/wheel and run twine check"
	@echo "  make publish   Verify API token, then upload current version to PyPI"
	@echo "  make wiki      Publish wiki/*.md pages to GitHub Wiki"
	@echo "  make version   Print current version"

ensure-venv:
	@if [ ! -x "$(PYTHON)" ]; then \
		echo "Missing $(PYTHON). Create venv first:"; \
		echo "  python3 -m venv .venv && .venv/bin/pip install -e '.[all,dev]' build twine"; \
		exit 1; \
	fi

check: ensure-venv
	@$(PYTHON) tools/release.py check

version: ensure-venv
	@$(PYTHON) tools/release.py version

bump: ensure-venv
	@$(PYTHON) tools/release.py bump

test: ensure-venv
	PYTHONPATH=. $(PYTEST) -q

build: ensure-venv
	@$(PYTHON) tools/release.py build

# Always verify API token before upload.
publish: check
	@$(PYTHON) tools/release.py publish

# Release flow verifies token first inside tools/release.py when PyPI upload is selected.
# Still run make check up front so bad tokens fail before interactive prompts.
release: check
	@$(PYTHON) tools/release.py release

wiki: ensure-venv
	@$(PYTHON) tools/publish_wiki.py

.PHONY: test test-fast frontend-build verify legacy-import purge-deleted

PYTHON ?= python3

# Full offline-capable regression suite.  Install test dependencies first:
# $(PYTHON) -m pip install -r webapp/backend/requirements-dev.txt
test:
	$(PYTHON) -m pytest -q tests webapp/backend/tests

# Fast syntax/build gate useful before committing a focused change.
test-fast:
	$(PYTHON) -m py_compile run_analyst_pipeline.py scripts/*.py webapp/backend/*.py

frontend-build:
	cd webapp/frontend && npm run build

verify: test test-fast frontend-build

# Explicit operational commands; neither modifies data without its --apply flag.
legacy-import:
	$(PYTHON) -m webapp.backend.legacy_import --source-dir reports --data-dir data

purge-deleted:
	$(PYTHON) -m webapp.backend.maintenance --data-dir data

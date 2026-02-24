PYTEST ?= pytest

.PHONY: install test test-unit test-component test-adapter test-contract test-e2e

install:
	pip install -e ".[dev]"

test: test-unit test-component test-contract test-e2e

test-unit:
	$(PYTEST) -m unit

test-component:
	$(PYTEST) -m component

test-adapter:
	$(PYTEST) -m adapter

test-contract:
	$(PYTEST) -m contract

test-e2e:
	$(PYTEST) -m e2e_smoke


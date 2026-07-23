# secure-ci-pipeline — convenience targets for local use.
# The CI pipeline does not depend on this file; it is purely for developers.

PYTHON ?= python3
ARTIFACTS ?= artifacts
POLICY ?= gate/policy.yml
REPORT ?= $(ARTIFACTS)/security-report.md

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Install the gate's runtime dependency (PyYAML)
	$(PYTHON) -m pip install pyyaml

.PHONY: demo
demo: ## Run the gate against the committed sample scan outputs
	@mkdir -p $(ARTIFACTS)
	$(PYTHON) gate/gate.py --artifacts samples --policy $(POLICY) --report $(REPORT)

.PHONY: gate
gate: ## Run the gate against a real artifacts/ directory
	$(PYTHON) gate/gate.py --artifacts $(ARTIFACTS) --policy $(POLICY) --report $(REPORT)

.PHONY: report
report: ## Render the Markdown report from the sample scan outputs
	$(PYTHON) gate/report.py --artifacts samples --policy $(POLICY) --output $(REPORT)

.PHONY: build
build: ## Build the vulnerable app image
	docker compose build

.PHONY: up
up: ## Run the vulnerable app locally on http://localhost:5000
	docker compose up -d

.PHONY: down
down: ## Stop the vulnerable app
	docker compose down --remove-orphans

.PHONY: clean
clean: ## Remove generated artifacts and local databases
	rm -rf $(ARTIFACTS) vulnerable_app/bank.db
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

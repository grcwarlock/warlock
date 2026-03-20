.PHONY: install test lint migrate dev clean seed help qa qa-quick verify-docs demo cli

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies (dev mode)
	pip install -e ".[dev,aws,ai]"

test: ## Run test suite
	pytest tests/ -v --tb=short

lint: ## Run linter
	ruff check warlock/

qa: ## Run full QA gate (must pass before commit)
	./scripts/qa.sh

qa-quick: ## Quick QA (lint + test only, ~30s)
	./scripts/qa.sh --quick

verify-docs: ## Check documentation counts match reality
	.venv/bin/python scripts/verify_docs.py --verbose

migrate: ## Run database migrations
	alembic upgrade head

dev: ## Start local dev environment (docker-compose)
	docker compose up -d
	@echo "Waiting for services..."
	@sleep 3
	@echo "Running migrations..."
	WLK_DATABASE_URL=postgresql://warlock:warlock_dev@localhost:5432/warlock alembic upgrade head
	@echo "Ready: http://localhost:8000/api/v1/health"

seed: ## Run demo seed
	python scripts/demo_seed.py

demo: ## Spin up full demo (DB + OPA + API + seed) in one command
	./scripts/demo.sh
	@echo ""
	@echo "  ⚠  Run this to use CLI commands:"
	@echo ""
	@echo "     source .venv/bin/activate"
	@echo ""

cli: ## Activate venv and show available commands
	@echo "Run this in your terminal:"
	@echo ""
	@echo "  source .venv/bin/activate"
	@echo "  warlock --help"
	@echo ""

clean: ## Stop dev environment and clean up
	docker compose down -v
	rm -f warlock.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

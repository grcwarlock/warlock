.PHONY: install test lint migrate clean seed reset help qa qa-quick verify-docs demo cli frontend-install frontend-dev frontend-build tui warlock

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

seed: ## Run demo seed
	WLK_AI_ENABLED=false python scripts/demo_seed.py

reset: ## Reset SQLite DB and seed fresh data
	rm -f warlock.db warlock.db-shm warlock.db-wal
	rm -rf lake/
	.venv/bin/alembic upgrade head
	WLK_AI_ENABLED=false .venv/bin/python scripts/demo_seed.py

warlock: reset ## Reset DB, seed, and launch the TUI
	.venv/bin/warlock

tui: ## Launch the TUI (assumes DB is seeded)
	.venv/bin/warlock

demo: ## Spin up full demo (DB + OPA + API + seed) and drop into CLI-ready shell
	@./scripts/demo.sh

cli: ## Activate venv and show available commands
	@echo "Run this in your terminal:"
	@echo ""
	@echo "  source .venv/bin/activate"
	@echo "  warlock --help"
	@echo ""

frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-dev: ## Start frontend dev server (proxy to API on :8000)
	cd frontend && npm run dev

frontend-build: ## Build frontend for production
	cd frontend && npm ci && npm run build

clean: ## Clean up DB, lake, and __pycache__
	rm -f warlock.db warlock.db-shm warlock.db-wal
	rm -rf lake/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

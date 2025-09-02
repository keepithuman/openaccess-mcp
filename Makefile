.PHONY: help install install-dev test lint format clean docker-build docker-run

help: ## Show this help message
	@echo "OpenAccess MCP - Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	pip install -e .

install-dev: ## Install the package with development dependencies
	pip install -e ".[dev]"

test: ## Run tests
	pytest

test-cov: ## Run tests with coverage
	pytest --cov=openaccess_mcp --cov-report=html

lint: ## Run linting
	ruff check .
	mypy openaccess_mcp/

format: ## Format code
	ruff format .
	black openaccess_mcp/

clean: ## Clean up build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

docker-build: ## Build Docker image
	docker build -t openaccess-mcp .

docker-run: ## Run Docker container
	docker run -p 8080:8080 -v $(PWD)/examples/profiles:/app/profiles openaccess-mcp

docker-compose-up: ## Start services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

generate-keys: ## Generate new audit signing keys
	openaccess-mcp generate-keys

profiles: ## List available profiles
	openaccess-mcp profiles

audit-stats: ## Show audit log statistics
	openaccess-mcp audit

verify-audit: ## Verify audit log integrity
	openaccess-mcp verify

dev-setup: install-dev generate-keys ## Set up development environment
	@echo "Development environment setup complete!"
	@echo "Run 'make docker-compose-up' to start demo services"
	@echo "Run 'make test' to run tests"

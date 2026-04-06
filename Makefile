# Makefile for Forensic Security Scanner

.PHONY: help install install-dev test lint format clean run run-signatures run-brainwallets run-forensics db-init db-migrate docker-build docker-run

# Default target
help:
	@echo "Forensic Security Scanner - Available Commands:"
	@echo ""
	@echo "  make install          - Install production dependencies"
	@echo "  make install-dev      - Install development dependencies"
	@echo "  make test             - Run tests"
	@echo "  make lint             - Run linters"
	@echo "  make format           - Format code with black"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make run              - Run full scan"
	@echo "  make run-signatures   - Run signature scan only"
	@echo "  make run-brainwallets - Run brain wallet scan only"
	@echo "  make run-forensics    - Run forensic analysis"
	@echo "  make db-init          - Initialize database"
	@echo "  make db-migrate       - Run database migrations"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make docker-run       - Run with Docker"
	@echo ""

# Installation
install:
	pip install -r requirements.txt

install-dev: install
	pip install -e ".[dev]"

# Testing
test:
	python -m pytest tests/ -v --tb=short

test-coverage:
	python -m pytest tests/ -v --cov=forensic_scanner --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 forensic_scanner/ --max-line-length=100 --ignore=E501,W503
	mypy forensic_scanner/ --ignore-missing-imports

format:
	black forensic_scanner/ tests/ --line-length=100

format-check:
	black forensic_scanner/ tests/ --line-length=100 --check

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

# Running scans
run:
	python main.py --mode full --start-block 0 --end-block 336000

run-signatures:
	python main.py --mode signatures --start-block 0 --end-block 336000

run-brainwallets:
	python main.py --mode brainwallets --start-block 0 --end-block 336000

run-forensics:
	python main.py --mode forensics --start-block 0 --end-block 336000

run-quick:
	python main.py --mode signatures --start-block 0 --end-block 10000

# Database
db-init:
	mkdir -p data
	python -c "from database.models import DatabaseManager; from config.settings import DatabaseConfig; db = DatabaseManager(DatabaseConfig().connection_string); db.create_tables(); print('Database initialized')"

db-reset:
	@echo "WARNING: This will delete all data!"
	@read -p "Are you sure? [y/N] " confirm && [ $$confirm = y ] && rm -f data/*.db || echo "Cancelled"

db-stats:
	python -c "from database.models import DatabaseManager; from config.settings import DatabaseConfig; db = DatabaseManager(DatabaseConfig().connection_string); session = db.get_session(); print('Connected to database')"

# Docker
docker-build:
	docker build -t forensic-scanner:latest .

docker-run:
	docker run --rm -it \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/output:/app/output \
		-v $(PWD)/logs:/app/logs \
		forensic-scanner:latest \
		--mode full --start-block 0 --end-block 336000

# Development
dev-setup:
	python -m venv venv
	. venv/bin/activate && pip install -r requirements.txt
	. venv/bin/activate && pip install -e ".[dev]"
	mkdir -p data wordlists logs output
	cp .env.example .env

# Utilities
generate-wordlists:
	python scripts/generate_wordlists.py

export-results:
	python scripts/export_results.py

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "Documentation will be available in docs/"

# Performance profiling
profile:
	python -m cProfile -o profile.stats main.py --mode signatures --start-block 0 --end-block 1000
	python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(50)"

# Memory profiling
mem-profile:
	python -m memory_profiler main.py --mode signatures --start-block 0 --end-block 1000

# Benchmark
benchmark:
	python scripts/benchmark.py

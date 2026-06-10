.PHONY: install install-dev test lint binary clean

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-quick:
	pytest tests/ -v -x --tb=short

binary:
	pyinstaller --onefile --name falcon-billing \
		--add-data "falcon_billing/web/templates:falcon_billing/web/templates" \
		--add-data "falcon_billing/web/static:falcon_billing/web/static" \
		--hidden-import flask \
		--hidden-import falconpy \
		falcon_billing/cli/main.py

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

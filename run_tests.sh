#!/bin/bash
# Test runner script for local development

set -e

echo "=== Running PublicInspector Test Suite ==="
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt
pip install -q -r requirements-dev.txt
pip install -q -e .

echo ""
echo "=== Running Tests ==="
pytest tests/ -v

echo ""
echo "=== Running Linters ==="
echo "  - flake8"
flake8 publicinspector/ || true

echo "  - black (check only)"
black --check publicinspector/ || true

echo "  - isort (check only)"
isort --check-only publicinspector/ || true

echo ""
echo "=== Running Security Checks ==="
echo "  - bandit"
bandit -r publicinspector/ -ll || true

echo ""
echo "=== Test Suite Complete ==="

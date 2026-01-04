#!/bin/bash

# This script runs after the devcontainer is created

set -e

echo "🚀 Setting up PublicInspector development environment..."

# Upgrade pip
echo "📦 Upgrading pip..."
python -m pip install --upgrade pip

# Install project in editable mode with all dependencies
echo "📦 Installing PublicInspector and dependencies..."
pip install -e .

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -r requirements-dev.txt

# Set up pre-commit hooks (optional)
echo "🔧 Setting up git configuration..."
git config --global --add safe.directory /workspaces/PublicInspector

# Verify AWS CLI installation
echo "✅ Verifying AWS CLI..."
aws --version

# Check if AWS credentials are available
if [ -f "$HOME/.aws/credentials" ]; then
    echo "✅ AWS credentials found at $HOME/.aws/credentials"
else
    echo "⚠️  AWS credentials not found. Please configure AWS credentials."
    echo "   You can either:"
    echo "   1. Mount credentials from your host machine (already configured in devcontainer.json)"
    echo "   2. Run 'aws configure' inside the container"
fi

# Run tests to verify setup
echo "🧪 Running tests to verify setup..."
python -m pytest tests/ -v --tb=short || echo "⚠️  Some tests failed. This is OK if you don't have AWS credentials configured."

echo ""
echo "✨ DevContainer setup complete!"
echo ""
echo "📚 Quick Start:"
echo "   - Run tests: ./run_tests.sh"
echo "   - Run tool: python -m publicinspector.cli --help"
echo "   - Configure AWS: aws configure (if not already done)"
echo "   - List plugins: python -m publicinspector.cli scan --list-plugins"
echo ""

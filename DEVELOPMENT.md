# Development Guide

## Quick Start with DevContainer

The fastest way to get started developing PublicInspector is using the provided DevContainer:

1. Install [VS Code](https://code.visualstudio.com/), [Docker Desktop](https://www.docker.com/products/docker-desktop/), and the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Clone this repository
3. Open in VS Code and click "Reopen in Container"
4. Wait for the container to build (first time only)
5. Start coding!

## Project Structure

```
PublicInspector/
├── .devcontainer/          # DevContainer configuration
│   ├── devcontainer.json   # Container settings
│   └── post-create.sh      # Setup script
├── .github/                # GitHub Actions workflows
├── .vscode/                # VS Code settings and launch configs
├── publicinspector/        # Main package
│   ├── plugins/            # Service scanner plugins
│   ├── cli.py              # Command-line interface
│   ├── scanner.py          # Scan orchestration
│   ├── config.py           # Configuration management
│   ├── aws_accounts.py     # Account utilities
│   └── output.py           # Output formatting
├── tests/                  # Test suite
│   ├── plugins/            # Plugin tests
│   └── conftest.py         # pytest configuration
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Development dependencies
└── setup.py                # Package setup

```

## Development Workflow

### Running Tests

```bash
# Run all tests
./run_tests.sh

# Run specific test file
python -m pytest tests/test_config.py -v

# Run with coverage
python -m pytest tests/ --cov=publicinspector --cov-report=html

# Run specific test
python -m pytest tests/test_config.py::TestConfig::test_organization_management -v
```

### Code Quality

The project uses several tools to maintain code quality:

```bash
# Format code with black
black publicinspector/ tests/

# Sort imports with isort
isort publicinspector/ tests/

# Lint with flake8
flake8 publicinspector/ tests/

# Type checking with mypy
mypy publicinspector/

# Security scanning
bandit -r publicinspector/
safety check
```

In the DevContainer, black and isort run automatically on save.

### Running the CLI

```bash
# Get help
python -m publicinspector.cli --help

# Scan single service
python -m publicinspector.cli scan --services s3

# Scan with custom regions
python -m publicinspector.cli scan --services s3 --regions us-east-1,us-west-2

# List available plugins
python -m publicinspector.cli scan --list-plugins

# Add organization
python -m publicinspector.cli add-org test-org --name "Test Org" --profile my-profile
```

### Debugging

VS Code launch configurations are provided in `.vscode/launch.json`:

1. **Python: Current File** - Debug the currently open Python file
2. **PublicInspector: Scan S3** - Debug S3 scanning
3. **PublicInspector: List Plugins** - Debug plugin listing
4. **Python: pytest** - Debug tests

To use:
1. Set breakpoints in your code
2. Press `F5` or go to Run and Debug panel
3. Select a configuration and click the green play button

## Adding a New Plugin

To add support for a new AWS service:

1. **Create plugin file** in `publicinspector/plugins/`:
   ```python
   # publicinspector/plugins/my_service_plugin.py
   from publicinspector.aws_base_plugin import AWSBasePlugin
   
   class MyServicePlugin(AWSBasePlugin):
       def get_service_name(self):
           return "myservice"
       
       def get_service_display_name(self):
           return "My Service"
       
       def scan_account_region(self, account_id, region):
           # Implementation here
           results = []
           # ... scan logic ...
           return results
   ```

2. **Add test file** in `tests/plugins/`:
   ```python
   # tests/plugins/test_my_service_plugin.py
   import pytest
   from publicinspector.plugins.my_service_plugin import MyServicePlugin
   
   def test_plugin_basics():
       plugin = MyServicePlugin()
       assert plugin.get_service_name() == "myservice"
   ```

3. **Update documentation** in README.md

4. **Run tests** to verify:
   ```bash
   python -m pytest tests/plugins/test_my_service_plugin.py -v
   ```

## AWS Credentials in Development

### Using AWS CLI Profiles

```bash
# List configured profiles
aws configure list-profiles

# Set active profile
export AWS_PROFILE=my-profile

# Verify credentials
aws sts get-caller-identity
```

### DevContainer Credential Mounting

The DevContainer automatically mounts your host machine's AWS credentials:
- Windows: `%USERPROFILE%\.aws` → `/home/vscode/.aws`
- Linux/Mac: `~/.aws` → `/home/vscode/.aws`

You can set environment variables in the devcontainer:
```bash
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1
```

Or configure them in `.devcontainer/devcontainer.json` under `remoteEnv`.

## Continuous Integration

GitHub Actions workflows run on every push:

- **CI Workflow** (`.github/workflows/ci.yml`):
  - Linting (black, isort, flake8)
  - Testing on Python 3.8, 3.9, 3.10, 3.11
  - Security scanning (bandit, safety)
  - Coverage reporting

- **CodeQL Workflow** (`.github/workflows/codeql.yml`):
  - Security vulnerability scanning
  - Code quality analysis

- **Dependency Review** (`.github/workflows/dependency-review.yml`):
  - Checks for vulnerable dependencies in PRs

## Releasing

1. Update version in `setup.py`
2. Update CHANGELOG (if exists)
3. Create a git tag:
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

## Troubleshooting

### DevContainer Issues

**Container fails to build:**
- Ensure Docker Desktop is running
- Check Docker has enough resources (4GB+ RAM recommended)
- Try rebuilding: `F1` → "Dev Containers: Rebuild Container"

**AWS credentials not accessible:**
- Verify credentials exist on host: `dir %USERPROFILE%\.aws` (Windows)
- Check mount configuration in `.devcontainer/devcontainer.json`
- Restart the container after changing credentials

**VS Code extensions not loading:**
- Rebuild the container: `F1` → "Dev Containers: Rebuild Container"
- Check extension compatibility with container Python version

### Testing Issues

**Tests fail with AWS errors:**
- Tests use mocked AWS calls and shouldn't require credentials
- If integration tests fail, ensure you have valid AWS credentials
- Use `pytest -v` for detailed error messages

**Import errors:**
- Ensure package is installed in editable mode: `pip install -e .`
- Check Python path: `python -c "import sys; print(sys.path)"`

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `./run_tests.sh`
5. Run linters: `black . && isort . && flake8`
6. Commit changes: `git commit -am "Add my feature"`
7. Push to branch: `git push origin feature/my-feature`
8. Create a Pull Request

## Resources

- [AWS Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Click CLI Framework](https://click.palletsprojects.com/)
- [pytest Documentation](https://docs.pytest.org/)
- [VS Code DevContainers](https://code.visualstudio.com/docs/devcontainers/containers)

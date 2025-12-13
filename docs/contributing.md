# Contributing to DSP Scanner

First off, thank you for considering contributing to DSP Scanner! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Poetry for dependency management
- Git for version control
- Docker for containerization (optional)

### Initial Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/akintunero/devsecops-policy-scanner.git
   cd dsp-scanner
   ```

3. Set up development environment:
   ```bash
   # Install poetry
   curl -sSL https://install.python-poetry.org | python3 -

   # Install dependencies
   poetry install

   # Set up pre-commit hooks
   poetry run pre-commit install
   ```

## Development Setup

### Project Structure

```
dsp-scanner/
├── src/
│   └── dsp_scanner/
│       ├── core/          # Core functionality
│       ├── scanners/      # Platform-specific scanners
│       ├── ml/           # Machine learning components
│       └── utils/        # Utility functions
├── tests/                # Test suite
├── docs/                # Documentation
└── examples/            # Example configurations
```

### Virtual Environment

```bash
# Create and activate virtual environment
poetry shell

# Install development dependencies
poetry install --with dev
```

### Environment Variables

```bash
# Development settings
export DSP_SCANNER_ENV=development
export DSP_SCANNER_LOG_LEVEL=DEBUG

# Test settings
export DSP_SCANNER_TEST_DATA=/path/to/test/data
```

## Development Process

### 1. Create a Branch

```bash
# Create a new branch for your feature/fix
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Write your code
- Add tests
- Update documentation
- Run tests locally

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with a descriptive message
git commit -m "feat: add new feature"
```

Follow [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation
- `test:` for tests
- `refactor:` for refactoring
- `style:` for formatting changes
- `chore:` for maintenance

### 4. Push Changes

```bash
git push origin feature/your-feature-name
```

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use [Black](https://github.com/psf/black) for formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Use [mypy](http://mypy-lang.org/) for type checking

### Code Quality Tools

```bash
# Format code
poetry run black .

# Sort imports
poetry run isort .

# Type checking
poetry run mypy src/

# Lint code
poetry run flake8

# Run all checks
poetry run pre-commit run --all-files
```

### Documentation Standards

- Use Google-style docstrings
- Document all public APIs
- Include type hints
- Provide examples for complex functionality

Example:
```python
def scan_file(
    path: Path,
    options: Optional[Dict[str, Any]] = None
) -> ScanResult:
    """
    Scan a file for security issues.

    Args:
        path: Path to the file to scan
        options: Optional scanning options

    Returns:
        ScanResult containing the findings

    Raises:
        FileNotFoundError: If the file doesn't exist
        ScanError: If scanning fails
    """
    ...
```

## Testing Guidelines

### Writing Tests

- Use pytest for testing
- Write unit tests for all new code
- Include integration tests for complex features
- Add performance tests for critical paths

Example:
```python
@pytest.mark.asyncio
async def test_scanner_with_custom_policy():
    scanner = Scanner()
    policy = create_test_policy()
    result = await scanner.scan_with_policy("test.txt", policy)
    assert result.findings
    assert result.findings[0].severity == Severity.HIGH
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=dsp_scanner

# Run specific test file
poetry run pytest tests/test_scanner.py

# Run tests by marker
poetry run pytest -m "integration"
```

### Test Categories

Use pytest markers to categorize tests:
```python
@pytest.mark.unit
@pytest.mark.integration
@pytest.mark.performance
@pytest.mark.security
```

## Documentation

### Building Documentation

```bash
# Install documentation dependencies
poetry install --with docs

# Build documentation
poetry run mkdocs build

# Serve documentation locally
poetry run mkdocs serve
```

### Documentation Structure

1. API Reference
   - Document all public APIs
   - Include type information
   - Provide examples

2. User Guides
   - Step-by-step tutorials
   - Use case examples
   - Best practices

3. Developer Guides
   - Architecture overview
   - Development setup
   - Contributing guidelines

## Submitting Changes

### Pull Request Process

1. Update documentation
2. Add/update tests
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit pull request

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code cleanup

## Testing
- [ ] Added unit tests
- [ ] Added integration tests
- [ ] Tested manually

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] CHANGELOG.md updated
```

### Review Process

1. Automated checks must pass
2. Code review by maintainers
3. Documentation review
4. Test coverage review
5. Final approval

## Release Process

1. Version bump
   ```bash
   poetry version patch  # or minor/major
   ```

2. Update CHANGELOG.md

3. Create release commit
   ```bash
   git commit -am "release: v1.0.0"
   ```

4. Create tag
   ```bash
   git tag -a v1.0.0 -m "Version 1.0.0"
   ```

5. Push changes
   ```bash
   git push origin main --tags
   ```


## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to DSP Scanner!

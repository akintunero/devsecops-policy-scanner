# Contributing to devsecops-policy-scanner

First off, thank you for considering contributing to devsecops-policy-scanner! It's people like you that make this project such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report, please check the issue list to avoid duplicates. When creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples demonstrating the issue
- Describe the observed behavior after following the steps
- Explain the expected behavior and why
- Include screenshots if applicable
- Provide your environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When suggesting an enhancement, please include:

- A clear and descriptive title
- A step-by-step description of the proposed enhancement
- Examples demonstrating the enhancement
- Describe current behavior and expected behavior
- Explain why this enhancement would be useful
- Mention other tools or applications where this enhancement exists

### Pull Requests

- Fill in the required pull request template
- Do not include issue numbers in the PR title
- Include screenshots or GIFs to demonstrate changes where applicable
- Follow Python style guides
- Include well-structured and thoughtful tests
- Document new code clearly
- End all files with a newline

## Development Process

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`poetry run pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Setting Up Development Environment

```bash
# Clone your fork
git clone https://github.com/akintunero/devsecops-policy-scanner.git
cd devsecops-policy-scanner

# Install poetry
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Setup pre-commit hooks
poetry run pre-commit install

```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=dsp_scanner

# Run specific test file
poetry run pytest tests/test_specific.py
```

### Code Style

We use the following tools to maintain code quality:

* black for code formatting
* flake8 for style guide enforcement
* mypy for static type checking
* isort for import sorting

```bash
# Format code
poetry run black .

# Check style
poetry run flake8

# Check types
poetry run mypy src/

# Sort imports
poetry run isort .
```

## Project Structure

```
devsecops-policy-scanner/
├── src/
│   └── dsp_scanner/
│       ├── core/          # Core functionality
│       ├── scanners/      # Platform-specific scanners
│       ├── ml/            # Machine learning components
│       └── utils/         # Utility functions
├── tests/                 # Test suite
├── docs/                  # Documentation
└── examples/              # Example configurations

```

## Writing Documentation

* Use docstrings for all public modules, functions, classes, and methods
* Follow Google style for docstrings
* Update README.md with any new features
* Add examples for new features

## Creating a New Scanner

1. Create a new file in `src/dsp_scanner/scanners/`
2. Implement the scanner interface
3. Add tests in `tests/scanners/`
4. Update documentation
5. Add examples

Example scanner structure:

```python
from typing import List, Optional
from pathlib import Path

from dsp_scanner.core.results import Finding, ScanResult
from dsp_scanner.core.policy import Policy

class NewScanner:
    async def scan(
        self,
        path: Path,
        policies: Optional[List[Policy]] = None
    ) -> ScanResult:
        # Implementation
        pass
```

## Release Process

1. Update version in pyproject.toml
2. Update CHANGELOG.md
3. Create a new tag
4. Push tag to trigger release workflow

## Questions?

Feel free to open an issue with your question or contact the maintainers directly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

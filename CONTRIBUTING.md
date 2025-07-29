# Contributing to DevSecOps Policy Scanner

Thank you for your interest in contributing to the DevSecOps Policy Scanner! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Community](#community)

## Getting Started

### Prerequisites

- Python 3.9+ (3.11 recommended)
- Git
- Docker (optional, for containerized development)
- Make (optional, for using Makefile commands)

### Quick Start

1. **Fork the repository**
   ```bash
   git clone https://github.com/akintunero/devsecops-policy-scanner.git
   cd devsecops-policy-scanner
   ```

2. **Set up development environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   pip install -e .
   ```

3. **Run tests**
   ```bash
   pytest tests/ -v
   ```

## Development Setup

### Local Development

1. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/devsecops-policy-scanner.git
   cd devsecops-policy-scanner
   ```

2. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/akintunero/devsecops-policy-scanner.git
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   pip install -e .
   ```

### Docker Development

1. **Build development image**
   ```bash
   docker build -t devsecops-policy-scanner:dev --target development .
   ```

2. **Run development container**
   ```bash
   docker run -it --rm -v $(pwd):/app devsecops-policy-scanner:dev
   ```

3. **Use Docker Compose**
   ```bash
   docker-compose up dsp-scanner-dev
   ```

## Code Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- **Line length**: 120 characters maximum
- **Import order**: Standard library, third-party, local imports
- **Docstrings**: Google style docstrings
- **Type hints**: Required for all public functions

### Code Formatting

We use automated tools for code formatting:

```bash
# Format code with Black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Check code style with flake8
flake8 src/ tests/ --max-line-length=120

# Type checking with MyPy
mypy src/ --ignore-missing-imports
```

### Pre-commit Hooks

Install pre-commit hooks for automatic formatting:

```bash
pip install pre-commit
pre-commit install
```

### Code Quality Tools

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **MyPy**: Type checking
- **Pylint**: Additional linting
- **Bandit**: Security linting

## Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v

# Run specific test function
pytest tests/test_scanner.py::test_scan_policy -v
```

### Test Structure

```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── performance/    # Performance tests
├── security/       # Security tests
└── conftest.py     # Test configuration
```

### Writing Tests

1. **Test naming**: `test_<function_name>_<scenario>`
2. **Use fixtures**: Reuse common test data
3. **Mock external dependencies**: Don't rely on external services
4. **Test edge cases**: Include error conditions
5. **Maintain test isolation**: Each test should be independent

### Example Test

```python
import pytest
from src.dsp_scanner.core.scanner import PolicyScanner

def test_scan_policy_valid_input():
    """Test scanning a valid policy file."""
    scanner = PolicyScanner()
    result = scanner.scan("tests/fixtures/valid_policy.yaml")
    
    assert result.is_valid
    assert len(result.violations) == 0
    assert result.score >= 0.8

def test_scan_policy_invalid_input():
    """Test scanning an invalid policy file."""
    scanner = PolicyScanner()
    
    with pytest.raises(ValueError):
        scanner.scan("tests/fixtures/invalid_policy.yaml")
```

## Documentation

### Documentation Standards

- **README.md**: Project overview and quick start
- **docs/**: Detailed documentation
- **Inline comments**: Explain complex logic
- **Docstrings**: Google style for all public functions
- **Type hints**: Required for all public APIs

### Building Documentation

```bash
# Install documentation dependencies
pip install sphinx sphinx-rtd-theme

# Build documentation
sphinx-build -b html docs/ docs/_build/html

# Serve documentation locally
python -m http.server 8000 -d docs/_build/html
```

### Documentation Structure

```
docs/
├── api/              # API documentation
├── guides/           # User guides
├── development/      # Developer documentation
├── security/         # Security documentation
└── index.rst         # Main documentation index
```

## Security

### Security Guidelines

1. **Never commit secrets**: Use environment variables or secure storage
2. **Validate inputs**: Always validate and sanitize user inputs
3. **Use secure defaults**: Implement secure-by-default configurations
4. **Follow OWASP guidelines**: Adhere to OWASP security best practices
5. **Report vulnerabilities**: Use our security policy for vulnerability reports

### Security Testing

```bash
# Run security scans
bandit -r src/ -f json -o bandit-report.json
safety check --json --output safety-report.json

# Run vulnerability scans
pip-audit --json --output pip-audit-report.json
```

### Security Review Process

1. **Code review**: All code changes require security review
2. **Dependency review**: Automated dependency vulnerability scanning
3. **Security testing**: Automated security tests in CI/CD
4. **Penetration testing**: Regular security assessments

## Pull Request Process

### Before Submitting

1. **Update documentation**: Ensure documentation is up to date
2. **Add tests**: Include tests for new functionality
3. **Run tests**: Ensure all tests pass locally
4. **Check formatting**: Run code formatting tools
5. **Security review**: Ensure no security issues

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass locally

## Documentation
- [ ] README updated
- [ ] API documentation updated
- [ ] Code comments added

## Security
- [ ] Security implications considered
- [ ] No security vulnerabilities introduced
- [ ] Security tests added if applicable

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] Security review completed
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs automatically
2. **Code review**: At least one maintainer review required
3. **Security review**: Security team review for sensitive changes
4. **Documentation review**: Ensure documentation is complete
5. **Final approval**: Maintainer approval for merge

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible features
- **PATCH**: Backward-compatible bug fixes

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security scan clean
- [ ] Performance benchmarks acceptable
- [ ] Release notes prepared
- [ ] Docker images built and tested
- [ ] GitHub release created

### Release Steps

1. **Update version**: Update version in setup.py and __init__.py
2. **Update changelog**: Add release notes to CHANGELOG.md
3. **Create release branch**: `git checkout -b release/vX.Y.Z`
4. **Run full test suite**: Ensure all tests pass
5. **Create GitHub release**: Tag and release on GitHub
6. **Deploy**: Deploy to PyPI and Docker Hub

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security**: akintunero101@gmail.com for security issues
- **Email**: akintunero101@gmail.com for general inquiries

### Community Guidelines

- **Be respectful**: Follow our Code of Conduct
- **Be helpful**: Help others learn and grow
- **Be patient**: Understand different experience levels
- **Be constructive**: Provide helpful feedback
- **Be collaborative**: Work together toward common goals

### Recognition

We recognize contributors in several ways:

- **Contributor profiles**: Featured on our website
- **Release notes**: Acknowledged in release announcements
- **Hall of Fame**: Listed in project documentation
- **Special thanks**: Recognized for significant contributions

## Getting Help

### Common Issues

1. **Installation problems**: Check Python version and dependencies
2. **Test failures**: Ensure all dependencies are installed
3. **Documentation issues**: Check if documentation is up to date
4. **Security concerns**: Follow our security policy

### Resources

- **Documentation**: [Project Documentation](docs/)
- **Issues**: [GitHub Issues](https://github.com/akintunero/devsecops-policy-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/akintunero/devsecops-policy-scanner/discussions)
- **Security**: [Security Policy](SECURITY.md)

### Contact

- **General**: akintunero101@gmail.com
- **Security**: akintunero101@gmail.com
- **Maintainer**: Olúmáyòwá Akinkuehinmi (akintunero101@gmail.com)

---

**Thank you for contributing to DevSecOps Policy Scanner!**

**Last Updated**: January 2025  
**Maintainer**: Olúmáyòwá Akinkuehinmi (akintunero101@gmail.com)

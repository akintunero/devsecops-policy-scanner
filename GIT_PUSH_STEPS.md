# Git Push Steps for DevSecOps Policy Scanner

This document outlines the standard git push workflow for the DevSecOps Policy Scanner project.

## Prerequisites

1. Ensure you have the latest changes from the remote repository
2. Make sure all tests pass locally
3. Verify your changes follow the project's coding standards

## Standard Git Push Workflow

### 1. Check Current Status
```bash
git status
```
This shows which files have been modified, added, or deleted.

### 2. Add Changes to Staging
```bash
# Add all changes
git add .

# Or add specific files
git add <filename>
```

### 3. Commit Changes
```bash
# Single comprehensive commit for major feature implementation:
git commit -m "feat: implement comprehensive DevSecOps policy scanner

- Add CIS and OWASP policy scanning with multi-framework support
- Implement Kubernetes pod security policy validation
- Integrate Docker container security scanning capabilities
- Add Terraform infrastructure security checks
- Implement ML-based security analysis for advanced threat detection
- Add GitHub Actions integration with automated scanning workflows
- Create beautiful CLI interface using Rich library for enhanced UX
- Add multi-format reporting support (JSON, HTML, CSV)
- Fix policy validation issues in advanced_scanner.py
- Correct severity filtering in enhanced_cli.py
- Update README with comprehensive scanning capabilities
- Add unit tests for Kubernetes scanner and integration tests
- Refactor policy loading in enhanced_policy_engine.py
- Update dependencies for security scanning tools

This commit delivers a complete DevSecOps policy scanning solution
with enterprise-grade security compliance capabilities."

# Or use conventional commits format for individual changes:
git commit -m "feat: implement CIS and OWASP policy scanning"
git commit -m "feat: add Kubernetes pod security policy validation"
git commit -m "feat: integrate Docker container security scanning"
git commit -m "feat: add Terraform infrastructure security checks"
git commit -m "feat: implement ML-based security analysis"
git commit -m "feat: add GitHub Actions integration with automated scanning"
git commit -m "feat: create beautiful CLI interface with Rich library"
git commit -m "feat: add multi-format reporting (JSON, HTML, CSV)"
git commit -m "fix: resolve policy validation issue in advanced_scanner.py"
git commit -m "fix: correct severity filtering in enhanced_cli.py"
git commit -m "docs: update README with new scanning capabilities"
git commit -m "test: add unit tests for Kubernetes scanner"
git commit -m "test: add integration tests for policy engine"
git commit -m "refactor: improve policy loading in enhanced_policy_engine.py"
git commit -m "chore: update dependencies for security scanning tools"
```

### 4. Pull Latest Changes (Recommended)
```bash
git pull origin main
```
This ensures you have the latest changes before pushing.

### 5. Push to Remote Repository
```bash
# Push to main branch
git push origin main

# Push to feature branch
git push origin <branch-name>
```

## Branch Workflow (Recommended)

### For New Features
```bash
# Create and switch to a new feature branch
git checkout -b feature/kubernetes-security-scanning

# Make your changes, then:
git add .
git commit -m "feat: implement Kubernetes pod security policy validation"
git push origin feature/kubernetes-security-scanning
```

### For Bug Fixes
```bash
# Create and switch to a bug fix branch
git checkout -b fix/advanced-scanner-validation

# Make your changes, then:
git add .
git commit -m "fix: resolve policy validation issue in advanced_scanner.py"
git push origin fix/advanced-scanner-validation
```

### For Documentation Updates
```bash
# Create and switch to a docs branch
git checkout -b docs/update-scanning-capabilities

# Make your changes, then:
git add .
git commit -m "docs: update README with new scanning capabilities"
git push origin docs/update-scanning-capabilities
```

## Commit Message Guidelines

Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `test:` for adding or updating tests
- `refactor:` for code refactoring
- `chore:` for maintenance tasks

## Pre-Push Checklist

Before pushing, ensure:
- [ ] All tests pass (`pytest`)
- [ ] Code follows PEP 8 standards
- [ ] Documentation is updated if needed
- [ ] Commit message is descriptive and follows conventions
- [ ] No sensitive information is being committed
- [ ] Security policies are properly validated
- [ ] CLI interface works correctly with new changes
- [ ] Policy engine loads all frameworks without errors
- [ ] Multi-format reporting generates valid outputs

## Troubleshooting

### If Push is Rejected
```bash
# Pull latest changes and rebase
git pull --rebase origin main

# Or merge if rebase fails
git pull origin main
git push origin main
```

### If You Need to Force Push (Use with Caution)
```bash
git push --force-with-lease origin main
```

## Security Considerations

- Never commit API keys, passwords, or sensitive configuration
- Use environment variables for sensitive data
- Check `.gitignore` to ensure sensitive files are excluded
- Review changes before pushing to ensure no secrets are included

## Integration with CI/CD

The project uses GitHub Actions for continuous integration. Your push will trigger:
- Automated testing
- Code quality checks
- Security scanning
- Documentation generation

Make sure your changes pass all CI checks before merging to main. 
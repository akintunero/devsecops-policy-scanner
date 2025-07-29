# Enhanced DevSecOps Policy Scanner Makefile
# Provides convenient commands for development and usage

.PHONY: help install test scan clean lint format docs build docker-build docker-run

# Default target
help:
	@echo "🚀 Enhanced DevSecOps Policy Scanner"
	@echo "======================================"
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "📦 Installation & Setup:"
	@echo "  install          Install all dependencies"
	@echo "  install-dev      Install development dependencies"
	@echo "  install-tools    Install security scanning tools"
	@echo ""
	@echo "🔍 Scanning Commands:"
	@echo "  scan             Run basic security scan"
	@echo "  scan-verbose     Run verbose security scan"
	@echo "  scan-critical    Scan only critical severity issues"
	@echo "  scan-cis         Scan using CIS framework"
	@echo "  scan-owasp       Scan using OWASP framework"
	@echo "  scan-k8s         Scan Kubernetes manifests"
	@echo "  scan-docker      Scan Docker configurations"
	@echo "  scan-terraform   Scan Terraform code"
	@echo ""
	@echo "📊 Reporting & Analysis:"
	@echo "  list-policies    List all available policies"
	@echo "  summary          Show policy engine summary"
	@echo "  export-json      Export policies to JSON"
	@echo "  export-yaml      Export policies to YAML"
	@echo "  report-html      Generate HTML report"
	@echo ""
	@echo "🧪 Development:"
	@echo "  test             Run all tests"
	@echo "  test-coverage    Run tests with coverage"
	@echo "  lint             Run code linting"
	@echo "  format           Format code with black"
	@echo "  clean            Clean generated files"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-run       Run scanner in Docker"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs             Generate documentation"
	@echo "  docs-serve       Serve documentation locally"

# Installation targets
install:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt

install-dev:
	@echo "🔧 Installing development dependencies..."
	pip install -r requirements-dev.txt

install-tools:
	@echo "🛠️ Installing security scanning tools..."
	pip install bandit safety semgrep checkov trivy-python-plugin

# Scanning targets
scan:
	@echo "🔍 Running security scan..."
	python src/enhanced_cli.py scan . --format text

scan-verbose:
	@echo "🔍 Running verbose security scan..."
	python src/enhanced_cli.py scan . --verbose --format text

scan-critical:
	@echo "🚨 Scanning critical severity issues..."
	python src/enhanced_cli.py scan . --severity critical --format text

scan-cis:
	@echo "🛡️ Scanning with CIS framework..."
	python src/enhanced_cli.py scan . --framework CIS --format text

scan-owasp:
	@echo "🔐 Scanning with OWASP framework..."
	python src/enhanced_cli.py scan . --framework OWASP --format text

scan-k8s:
	@echo "☸️ Scanning Kubernetes manifests..."
	python src/enhanced_cli.py scan . --category pod_security --format text

scan-docker:
	@echo "🐳 Scanning Docker configurations..."
	python src/enhanced_cli.py scan . --category container_security --format text

scan-terraform:
	@echo "🏗️ Scanning Terraform code..."
	python src/enhanced_cli.py scan . --category infrastructure --format text

# Reporting targets
list-policies:
	@echo "📋 Listing all policies..."
	python src/enhanced_cli.py list-policies

summary:
	@echo "📊 Showing policy engine summary..."
	python src/enhanced_cli.py summary

export-json:
	@echo "📤 Exporting policies to JSON..."
	python src/enhanced_cli.py export --format json --output policies_export

export-yaml:
	@echo "📤 Exporting policies to YAML..."
	python src/enhanced_cli.py export --format yaml --output policies_export

report-html:
	@echo "📄 Generating HTML report..."
	python src/enhanced_cli.py scan . --format html --output security_report

# Development targets
test:
	@echo "🧪 Running tests..."
	pytest tests/ -v

test-coverage:
	@echo "🧪 Running tests with coverage..."
	pytest tests/ --cov=src --cov-report=html --cov-report=term

lint:
	@echo "🔍 Running code linting..."
	flake8 src/ tests/
	bandit -r src/

format:
	@echo "🎨 Formatting code..."
	black src/ tests/
	isort src/ tests/

clean:
	@echo "🧹 Cleaning generated files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.json" -path "./reports/*" -delete
	find . -type f -name "*.html" -path "./reports/*" -delete
	find . -type f -name "policies_export.*" -delete
	find . -type f -name "security_report.*" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/

# Docker targets
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t devsecops-policy-scanner .

docker-run:
	@echo "🐳 Running scanner in Docker..."
	docker run --rm -v $(PWD):/app devsecops-policy-scanner scan /app

# Documentation targets
docs:
	@echo "📚 Generating documentation..."
	mkdocs build

docs-serve:
	@echo "📚 Serving documentation locally..."
	mkdocs serve

# Advanced scanning targets
scan-comprehensive:
	@echo "🔍 Running comprehensive security scan..."
	python src/enhanced_cli.py scan . --verbose --format html --output comprehensive_report

scan-quick:
	@echo "⚡ Running quick security scan..."
	python src/enhanced_cli.py scan . --severity critical,high --format text

scan-custom:
	@echo "🎯 Running custom security scan..."
	python src/enhanced_cli.py scan . --category authentication,encryption --format json --output custom_report

# CI/CD targets
ci-scan:
	@echo "🤖 Running CI/CD security scan..."
	python src/enhanced_cli.py scan . --format json --output ci_report
	python src/advanced_scanner.py

ci-test:
	@echo "🤖 Running CI/CD tests..."
	pytest tests/ --cov=src --cov-report=xml
	flake8 src/ tests/
	bandit -r src/ -f json -o bandit-report.json

# Security analysis targets
analyze-secrets:
	@echo "🔐 Analyzing for secrets..."
	python src/advanced_scanner.py

analyze-dependencies:
	@echo "📦 Analyzing dependencies..."
	safety check --json --output safety-report.json

analyze-code:
	@echo "💻 Analyzing code security..."
	bandit -r src/ -f json -o bandit-report.json

# Utility targets
setup-dev:
	@echo "🚀 Setting up development environment..."
	make install
	make install-dev
	make install-tools
	@echo "✅ Development environment ready!"

demo:
	@echo "🎯 Running demo scan..."
	python src/enhanced_cli.py scan . --severity critical,high --format text
	@echo "📊 Generating demo report..."
	python src/enhanced_cli.py scan . --format html --output demo_report

validate:
	@echo "✅ Validating configuration..."
	python -c "from src.enhanced_policy_engine import EnhancedPolicyEngine; engine = EnhancedPolicyEngine(); print('✅ Policy engine loaded successfully')"
	@echo "✅ Configuration is valid!"

# Helpers
.PHONY: check-deps
check-deps:
	@echo "🔍 Checking dependencies..."
	python -c "import sys; print(f'Python version: {sys.version}')"
	pip list | grep -E "(typer|rich|pyyaml|click)"

.PHONY: version
version:
	@echo "📋 Scanner version information..."
	python -c "import sys; print(f'Python: {sys.version}')"
	python -c "import typer; print(f'Typer: {typer.__version__}')"
	python -c "import rich; print(f'Rich: {rich.__version__}')" 
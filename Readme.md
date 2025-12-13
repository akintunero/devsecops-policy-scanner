# 🚀 Enhanced DevSecOps Policy Scanner

**Advanced Security Policy Compliance & Infrastructure Scanning**

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-enhanced-red.svg)](SECURITY.md)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-automated-green.svg)](.github/workflows/enhanced_policy_scan.yml)

## 🎯 Overview

The **Enhanced DevSecOps Policy Scanner** is a comprehensive security compliance tool that scans infrastructure configurations, CI/CD settings, and repositories to enforce security policies **as code** before deployment. Built with advanced features for enterprise-grade security scanning.

## ✨ Key Features

### 🔒 **Advanced Policy Engine**
- **Multi-framework support**: CIS, OWASP, NIST, custom policies
- **Severity-based filtering**: Critical, High, Medium, Low, Info
- **Category-based organization**: Authentication, Encryption, Network, etc.
- **Dynamic policy loading** and validation
- **Risk scoring** and prioritization

### 🔍 **Multi-Platform Scanning**
- **Kubernetes**: Pod security, RBAC, network policies
- **Docker**: Container security, image vulnerabilities
- **Terraform**: Infrastructure as Code security
- **Python/JavaScript**: Code security analysis
- **General**: Secret detection, configuration validation

### 🎨 **Beautiful CLI Interface**
- **Rich terminal output** with colors and formatting
- **Progress indicators** for long scans
- **Interactive mode** for policy configuration
- **Multiple output formats**: Text, JSON, HTML, CSV
- **Comprehensive reporting** with visualizations

### 🤖 **AI-Powered Security Analysis**
- **ML-based risk prediction**: XGBoost models for risk scoring (0-100)
- **Anomaly detection**: Isolation Forest for unusual pattern detection
- **Zero-day prediction**: Ensemble models for zero-day vulnerability detection
- **No LLM APIs required**: All models run locally for privacy and cost efficiency

### 📡 **Real-Time Continuous Monitoring**
- **WebSocket-based live monitoring**: Real-time event streaming
- **Live dashboards**: Instant security posture visualization
- **Event history**: Complete audit trail of security events
- **Multi-client support**: Multiple simultaneous connections
- **Scalable architecture**: Horizontal scaling support

### 🏪 **Policy-as-Code Marketplace**
- **First-of-its-kind marketplace**: Share and discover security policies
- **Semantic versioning**: Policy versioning (e.g., 1.0.0, 1.1.0)
- **Community ratings**: Star ratings and reviews
- **Policy dependencies**: Policy composition and dependency management
- **Search & discovery**: Advanced search by tags, author, rating

### ✅ **Advanced Compliance Automation**
- **Multi-framework support**: CIS, NIST, HIPAA, PCI-DSS, SOC 2, ISO 27001, GDPR
- **Automated evidence collection**: Auto-generate compliance evidence
- **Cross-framework mapping**: Map controls across frameworks
- **Compliance scoring**: Automated compliance percentage calculation
- **Report generation**: JSON/YAML compliance reports

### 🔬 **Federated Learning for Security Patterns**
- **Privacy-preserving ML**: Train models without sharing raw data
- **Collaborative intelligence**: Share threat patterns anonymously
- **Differential privacy**: Add noise to protect individual data
- **Research potential**: Novel approach to collaborative security

### 🤖 **Advanced Automation**
- **GitHub Actions integration** with multi-stage scanning
- **Automated PR comments** with security insights
- **Security issue creation** for violations
- **Weekly scheduled scans** for continuous monitoring
- **Artifact management** for detailed reports

## 🛠️ Tech Stack

- **Python 3.8+** with modern async support
- **Rich & Typer** for beautiful CLI interfaces
- **PyYAML & JSON** for policy definitions
- **ML/AI**: scikit-learn, XGBoost, LightGBM (no LLM APIs - all local)
- **Real-Time**: WebSockets for live monitoring
- **Versioning**: Semantic versioning (semver) for policies
- **Security tools**: Bandit, Safety, Semgrep, Checkov, Trivy
- **Infrastructure**: Kubernetes, Docker, Terraform support
- **CI/CD**: GitHub Actions, GitLab CI, Azure DevOps

## 📋 Strategic Roadmap

This project is being enhanced with cutting-edge features for security policy compliance. For detailed information on:

- **Feature Roadmap**: See [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) for comprehensive feature plans
- **Visa Application Strategy**: See [VISA_APPLICATION_STRATEGY.md](VISA_APPLICATION_STRATEGY.md) for strategic planning
- **AI Engine Implementation**: See [IMPLEMENTATION_GUIDE_AI_ENGINE.md](IMPLEMENTATION_GUIDE_AI_ENGINE.md) for ML/AI implementation guide
- **Unified Platform Features**: See [UNIFIED_PLATFORM_FEATURES.md](UNIFIED_PLATFORM_FEATURES.md) for unified platform documentation
- **ML Approach (No LLM APIs)**: See [ML_APPROACH_NO_LLM.md](ML_APPROACH_NO_LLM.md) for traditional ML implementation

## 🚀 Quick Start

### 1. **Installation**

```bash
# Clone the repository
git clone https://github.com/akintunero/devsecops-policy-scanner.git
cd devsecops-policy-scanner

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

### 2. **Basic Usage**

```bash
# Scan current directory
python src/enhanced_cli.py scan .

# Scan with specific severity
python src/enhanced_cli.py scan . --severity critical

# Scan with framework filter
python src/enhanced_cli.py scan . --framework CIS

# Generate HTML report
python src/enhanced_cli.py scan . --format html --output report
```

### 3. **Advanced Commands**

```bash
# List all available policies
python src/enhanced_cli.py list-policies

# Show policy summary
python src/enhanced_cli.py summary

# Export policies to JSON
python src/enhanced_cli.py export --format json

# Scan with verbose output
python src/enhanced_cli.py scan . --verbose
```

### 4. **Unified Platform Usage**

```python
from dsp_scanner.platform import UnifiedSecurityPlatform
from dsp_scanner.compliance import ComplianceFramework

# Initialize unified platform with all features
platform = UnifiedSecurityPlatform(
    enable_monitoring=True,
    enable_marketplace=True,
    enable_compliance=True,
    enable_federated_learning=True
)

# Comprehensive scan with all features
result = await platform.scan_with_full_analysis(
    path="./infrastructure",
    frameworks=[ComplianceFramework.CIS, ComplianceFramework.NIST]
)

# Access all results
print(result['scan_result'])  # AI-powered scan results
print(result['compliance_reports'])  # Multi-framework compliance
print(result['monitoring']['dashboard_data'])  # Real-time metrics
```

### 5. **Policy Marketplace**

```python
from dsp_scanner.marketplace import PolicyRegistry

registry = PolicyRegistry()

# Search policies
policies = registry.search_policies(query="kubernetes", tags=["compliance"])

# Install policy
policy = registry.install_policy("cis-kubernetes", "1.0.0")
```

## 📋 Policy Frameworks

### **CIS Kubernetes Benchmark**
- Control plane security policies
- Worker node configurations
- Pod security standards
- Network policy enforcement
- RBAC and authentication

### **OWASP Top 10 2021**
- Broken Access Control (A01)
- Cryptographic Failures (A02)
- Injection vulnerabilities (A03)
- Insecure Design (A04)
- Security Misconfiguration (A05)
- Vulnerable Components (A06)
- Authentication Failures (A07)
- Software Integrity (A08)
- Logging Failures (A09)
- SSRF Protection (A10)

### **Custom Policies**
- Organization-specific security requirements
- Industry compliance standards
- Best practice enforcement
- Risk-based policy management

## 🔧 Configuration

### **Policy Definition**

Policies are defined in YAML format with advanced features:

```yaml
- key: enforce_2fa
  value: true
  description: "Two-Factor Authentication must be enabled"
  severity: "high"
  category: "authentication"
  framework: "CIS"
  control_id: "1.1.1"
  remediation: "Enable 2FA for all repository admins"
  tags: ["auth", "compliance"]
```

### **Scan Configuration**

```yaml
# config.yaml
scan_settings:
  severity_filter: ["critical", "high"]
  category_filter: ["authentication", "encryption"]
  framework_filter: ["CIS", "OWASP"]
  output_format: "html"
  verbose: true

reporting:
  include_remediation: true
  risk_scoring: true
  trend_analysis: true
```

## 📊 Output Formats

### **Text Output**
```
🔍 Scan Configuration
📁 Path: ./kubernetes-manifests
🎯 Severity Filter: All
🏷️  Category Filter: All
📚 Framework Filter: All

📊 Scan Results Summary
✅ Compliant: 15/20 (75.0%)
❌ Non-Compliant: 5/20 (25.0%)
🎯 Total Risk Score: 25.5
```

### **JSON Output**
```json
{
  "scan_results": [
    {
      "policy_key": "enforce_2fa",
      "compliant": false,
      "actual_value": false,
      "message": "❌ Two-Factor Authentication must be enabled",
      "risk_score": 7.5,
      "severity": "high",
      "category": "authentication"
    }
  ],
  "summary": {
    "total_policies": 20,
    "compliant": 15,
    "non_compliant": 5,
    "total_risk_score": 25.5
  }
}
```

### **HTML Report**
- Interactive dashboard with charts
- Detailed policy violation reports
- Remediation guidance
- Export capabilities

## 🔄 CI/CD Integration

### **GitHub Actions**

The scanner includes comprehensive GitHub Actions workflows:

```yaml
# .github/workflows/enhanced_policy_scan.yml
name: Enhanced Policy Compliance Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly scans
```

**Features:**
- Multi-stage scanning (Security, Dependencies, Infrastructure)
- Automated PR comments with security insights
- Security issue creation for violations
- Comprehensive artifact management
- Weekly scheduled scans

### **Other CI/CD Platforms**

```bash
# GitLab CI
python src/enhanced_cli.py scan . --format json --output gitlab-report

# Azure DevOps
python src/enhanced_cli.py scan . --format html --output azure-report

# Jenkins
python src/enhanced_cli.py scan . --format csv --output jenkins-report
```

## 🏗️ Advanced Scanning

### **Infrastructure Scanning**

```bash
# Kubernetes manifests
python src/enhanced_cli.py scan ./k8s-manifests --framework CIS

# Docker configurations
python src/enhanced_cli.py scan ./docker --category container_security

# Terraform code
python src/enhanced_cli.py scan ./terraform --framework infrastructure
```

### **Code Security Analysis**

```bash
# Python code
python src/enhanced_cli.py scan ./src --category code_security

# JavaScript/Node.js
python src/enhanced_cli.py scan ./frontend --category injection

# Mixed codebase
python src/enhanced_cli.py scan . --verbose --output comprehensive-report
```

## 📈 Monitoring & Reporting

### **Real-Time Continuous Monitoring Platform**
- **WebSocket-based live monitoring**: Sub-second event delivery
- **Live dashboards**: Real-time security posture visualization
- **Event streaming**: Complete audit trail of all security events
- **Multi-client support**: Handle 100+ concurrent connections
- **Metrics aggregation**: Total scans, active scans, findings, alerts, risk scores
- **Scalable architecture**: Horizontal scaling support

### **Comprehensive Reporting**
- Executive dashboards
- Trend analysis over time
- Compliance percentage tracking
- Remediation progress monitoring

### **Integration Capabilities**
- Prometheus metrics export
- Grafana dashboard templates
- Slack/Teams notifications
- Email alerting system

## 🔐 Security Features

### **Secret Detection**
- Hardcoded credentials scanning
- API key detection
- Token validation
- Environment variable checking

### **Vulnerability Assessment**
- Dependency vulnerability scanning
- CVE database integration
- Risk-based prioritization
- Remediation recommendations

### **Compliance Validation**
- Industry standard compliance
- Regulatory requirement checking
- Audit trail generation
- Compliance reporting

## 🚀 Performance & Scalability

### **Optimized Scanning**
- Parallel processing for large codebases
- Incremental scanning capabilities
- Caching mechanisms for repeated scans
- Resource usage optimization

### **Enterprise Features**
- Multi-tenant support
- Role-based access control
- Centralized policy management
- Audit logging and compliance

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**

```bash
# Clone and setup
git clone https://github.com/akintunero/devsecops-policy-scanner.git
cd devsecops-policy-scanner

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Format code
black src/
flake8 src/
```

### **Adding New Policies**

1. Create a new YAML file in `policies/`
2. Define policies with proper metadata
3. Add tests in `tests/`
4. Update documentation

## 📚 Documentation

- [API Reference](docs/api.md)
- [Policy Development Guide](docs/policy-development.md)
- [Integration Guide](docs/integration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Best Practices](docs/security-best-practices.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/akintunero/devsecops-policy-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/akintunero/devsecops-policy-scanner/discussions)
- **Security**: [Security Policy](SECURITY.md)

## 🙏 Acknowledgments

- CIS for Kubernetes benchmarks
- OWASP for security guidelines
- Open source security tools community
- Contributors and maintainers

---

**🔒 Secure your infrastructure with confidence!**



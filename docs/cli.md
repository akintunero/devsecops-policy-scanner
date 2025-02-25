# DSP Scanner CLI Guide

The DSP Scanner Command Line Interface (CLI) provides a powerful and flexible way to scan your infrastructure code for security issues. This guide explains all available commands and options.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Commands](#commands)
- [Options](#options)
- [Configuration](#configuration)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Integration](#integration)

## Installation

```bash
# Using pip
pip install dsp-scanner

# Using Docker
docker pull yourusername/dsp-scanner
```

## Basic Usage

```bash
# Basic scan
dsp-scanner scan ./path/to/project

# Scan with specific platforms
dsp-scanner scan --platform docker --platform kubernetes ./path/to/project

# Scan with AI analysis
dsp-scanner scan --ai ./path/to/project

# Generate detailed report
dsp-scanner scan --format html --output report.html ./path/to/project
```

## Commands

### scan
Scan infrastructure code for security issues.

```bash
dsp-scanner scan [OPTIONS] PATH
```

Options:
- `--platform, -p`: Platforms to scan (docker, kubernetes, terraform, helm)
- `--compliance, -c`: Compliance frameworks to check against
- `--severity, -s`: Minimum severity level to report
- `--ai/--no-ai`: Enable/disable AI-powered analysis
- `--format, -f`: Output format (text, json, html)
- `--output, -o`: Output file path
- `--verbose, -v`: Enable verbose output

### validate
Validate a custom policy file.

```bash
dsp-scanner validate [OPTIONS] POLICY_FILE
```

Options:
- `--strict`: Enable strict validation
- `--verbose`: Show detailed validation results

### init
Initialize DSP Scanner configuration in the current directory.

```bash
dsp-scanner init [OPTIONS] [PATH]
```

Options:
- `--force`: Overwrite existing configuration
- `--template`: Use specific template

## Options

### Global Options

```bash
# Version information
dsp-scanner --version

# Help
dsp-scanner --help

# Debug mode
dsp-scanner --debug

# Config file
dsp-scanner --config path/to/config.yml
```

### Scan Options

#### Platform Selection
```bash
# Single platform
dsp-scanner scan --platform docker ./

# Multiple platforms
dsp-scanner scan --platform docker --platform kubernetes ./

# All platforms
dsp-scanner scan --all-platforms ./
```

#### Compliance Frameworks
```bash
# Single framework
dsp-scanner scan --compliance cis ./

# Multiple frameworks
dsp-scanner scan --compliance cis --compliance nist ./
```

#### Severity Levels
```bash
# Minimum severity
dsp-scanner scan --severity high ./

# Include informational
dsp-scanner scan --severity info ./
```

#### AI Analysis
```bash
# Enable AI
dsp-scanner scan --ai ./

# Configure AI
dsp-scanner scan --ai --ai-confidence 0.8 ./
```

#### Output Control
```bash
# JSON output
dsp-scanner scan --format json ./

# HTML report
dsp-scanner scan --format html --output report.html ./

# Multiple formats
dsp-scanner scan --format json --format html ./
```

## Configuration

### Configuration File (.dsp-scanner.yml)

```yaml
scan:
  platforms:
    - docker
    - kubernetes
  severity_threshold: medium
  enable_ai: true
  compliance:
    - cis
    - nist

output:
  format: html
  path: reports/
  include_evidence: true

notifications:
  slack:
    webhook: https://hooks.slack.com/...
  email:
    to: security@example.com

ai:
  confidence_threshold: 0.8
  analysis_depth: deep
  features:
    - zero_day_detection
    - pattern_analysis
```

### Environment Variables

```bash
# Configuration
export DSP_SCANNER_CONFIG=/path/to/config.yml

# Authentication
export DSP_SCANNER_TOKEN=your_token

# Output
export DSP_SCANNER_OUTPUT_DIR=/path/to/reports
```

## Examples

### Basic Scanning

```bash
# Quick scan
dsp-scanner scan ./

# Detailed scan
dsp-scanner scan --verbose --format html ./
```

### Platform-Specific Scanning

```bash
# Docker scanning
dsp-scanner scan --platform docker ./Dockerfile

# Kubernetes scanning
dsp-scanner scan --platform kubernetes ./k8s/

# Terraform scanning
dsp-scanner scan --platform terraform ./terraform/

# Helm scanning
dsp-scanner scan --platform helm ./charts/
```

### Advanced Usage

```bash
# Comprehensive scan
dsp-scanner scan \
  --platform docker \
  --platform kubernetes \
  --compliance cis \
  --compliance nist \
  --severity medium \
  --ai \
  --format html \
  --output report.html \
  ./project/

# CI/CD integration
dsp-scanner scan \
  --ci \
  --format json \
  --fail-on-high \
  ./
```

## Output Formats

### Text Output (Default)
```bash
dsp-scanner scan ./
```
```
Security Scan Results
====================
Total Issues: 5
Critical: 1
High: 2
Medium: 2
...
```

### JSON Output
```bash
dsp-scanner scan --format json ./
```
```json
{
  "summary": {
    "total_issues": 5,
    "severity_counts": {
      "critical": 1,
      "high": 2,
      "medium": 2
    }
  },
  "findings": [...]
}
```

### HTML Report
```bash
dsp-scanner scan --format html --output report.html ./
```
Generates an interactive HTML report with:
- Executive summary
- Detailed findings
- Charts and graphs
- Remediation guidance

## Integration

### CI/CD Integration

#### GitHub Actions
```yaml
- name: Security Scan
  uses: dsp-scanner/action@v1
  with:
    path: ./
    platforms: docker,kubernetes
    format: sarif
```

#### GitLab CI
```yaml
security_scan:
  script:
    - dsp-scanner scan --ci --format json ./
```

#### Jenkins Pipeline
```groovy
stage('Security Scan') {
    steps {
        sh 'dsp-scanner scan --format html --output report.html ./'
    }
}
```

### API Integration

```python
from dsp_scanner.cli import scan

# Programmatic usage
result = scan(
    path="./",
    platforms=["docker", "kubernetes"],
    format="json"
)
```

## Exit Codes

- 0: Success, no issues found
- 1: Scan failed or error occurred
- 2: Issues found (with --fail-on-findings)
- 3: Configuration error
- 4: Invalid arguments

## Support

For questions and support:
- GitHub Issues: [Create an issue](https://github.com/yourusername/dsp-scanner/issues)
- Documentation: [Full documentation](https://dsp-scanner.readthedocs.io)
- Community: [Join our Discord](https://discord.gg/dsp-scanner)

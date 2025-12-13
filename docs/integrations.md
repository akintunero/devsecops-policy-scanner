# DSP Scanner Integrations Guide

This guide explains how to integrate DSP Scanner with various CI/CD platforms, development tools, and security systems.

## Table of Contents

- [CI/CD Integrations](#cicd-integrations)
- [IDE Integrations](#ide-integrations)
- [Cloud Platform Integrations](#cloud-platform-integrations)
- [Security Tool Integrations](#security-tool-integrations)
- [Custom Integrations](#custom-integrations)

## CI/CD Integrations

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install DSP Scanner
        run: pip install dsp-scanner
        
      - name: Run Security Scan
        uses: dsp-scanner/action@v1
        with:
          path: ./
          platforms: docker,kubernetes,terraform,helm
          format: sarif
          output: results.sarif
          
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  image: python:3.9
  script:
    - pip install dsp-scanner
    - dsp-scanner scan --format json --output scan-results.json ./
  artifacts:
    reports:
      security: scan-results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    python -m venv venv
                    . venv/bin/activate
                    pip install dsp-scanner
                    dsp-scanner scan \
                        --format html \
                        --output security-report.html \
                        ./
                '''
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.9'
    
- script: pip install dsp-scanner
  displayName: 'Install DSP Scanner'
  
- script: |
    dsp-scanner scan \
      --format json \
      --output $(Build.ArtifactStagingDirectory)/security-results.json \
      $(Build.SourcesDirectory)
  displayName: 'Run Security Scan'
  
- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: $(Build.ArtifactStagingDirectory)
    artifactName: SecurityResults
```

## IDE Integrations

### VS Code Extension

```json
{
    "dsp-scanner.enable": true,
    "dsp-scanner.scanOnSave": true,
    "dsp-scanner.platforms": [
        "docker",
        "kubernetes",
        "terraform",
        "helm"
    ],
    "dsp-scanner.severity": "medium"
}
```

### JetBrains Plugin

```xml
<idea-plugin>
    <id>com.dsp-scanner</id>
    <name>DSP Scanner</name>
    <vendor>DSP Scanner Team</vendor>
    
    <extensions defaultExtensionNs="com.intellij">
        <toolWindow id="DSP Scanner" secondary="true" icon="AllIcons.General.Modified" anchor="right" 
                    factoryClass="com.dspscanner.plugin.ScannerToolWindowFactory"/>
    </extensions>
</idea-plugin>
```

## Cloud Platform Integrations

### AWS Integration

```python
from dsp_scanner.integrations.aws import AWSIntegration

# Initialize AWS integration
aws = AWSIntegration(
    region="us-west-2",
    profile="security"
)

# Scan AWS resources
results = aws.scan_resources([
    "ec2",
    "s3",
    "rds",
    "iam"
])
```

### Azure Integration

```python
from dsp_scanner.integrations.azure import AzureIntegration

# Initialize Azure integration
azure = AzureIntegration(
    subscription_id="your-subscription-id",
    tenant_id="your-tenant-id"
)

# Scan Azure resources
results = azure.scan_resources([
    "compute",
    "storage",
    "network",
    "keyvault"
])
```

### GCP Integration

```python
from dsp_scanner.integrations.gcp import GCPIntegration

# Initialize GCP integration
gcp = GCPIntegration(
    project_id="your-project-id",
    credentials_file="path/to/credentials.json"
)

# Scan GCP resources
results = gcp.scan_resources([
    "compute",
    "storage",
    "iam",
    "network"
])
```

## Security Tool Integrations

### Jira Integration

```python
from dsp_scanner.integrations.jira import JiraIntegration

# Initialize Jira integration
jira = JiraIntegration(
    url="https://your-domain.atlassian.net",
    token="your-api-token",
    project="SEC"
)

# Create issues for findings
jira.create_issues(scan_results)
```

### Slack Integration

```python
from dsp_scanner.integrations.slack import SlackIntegration

# Initialize Slack integration
slack = SlackIntegration(
    webhook_url="https://hooks.slack.com/services/..."
)

# Send notifications
slack.notify_findings(scan_results)
```

### SIEM Integration

```python
from dsp_scanner.integrations.siem import SplunkIntegration

# Initialize Splunk integration
splunk = SplunkIntegration(
    host="splunk.example.com",
    port=8089,
    token="your-token"
)

# Send findings to Splunk
splunk.send_findings(scan_results)
```

## Custom Integrations

### REST API Integration

```python
from dsp_scanner.api import Scanner, APIClient

# Initialize API client
client = APIClient(
    base_url="https://api.example.com",
    api_key="your-api-key"
)

# Run scan through API
scanner = Scanner(api_client=client)
results = await scanner.scan_remote("repository-url")
```

### Webhook Integration

```python
from dsp_scanner.integrations.webhook import WebhookNotifier

# Initialize webhook notifier
notifier = WebhookNotifier(
    url="https://your-webhook.example.com",
    headers={
        "Authorization": "Bearer your-token"
    }
)

# Send webhook notifications
notifier.notify(scan_results)
```

### Custom Plugin Development

```python
from dsp_scanner.plugins import ScannerPlugin

class CustomScanner(ScannerPlugin):
    def __init__(self):
        super().__init__(
            name="custom-scanner",
            version="1.0.0"
        )
    
    async def scan(self, target):
        # Custom scanning logic
        return results
```

## Configuration Examples

### Integration Configuration File

```yaml
# .dsp-scanner-integrations.yml
integrations:
  github:
    enabled: true
    token: ${GITHUB_TOKEN}
    
  jira:
    enabled: true
    url: https://your-domain.atlassian.net
    token: ${JIRA_TOKEN}
    project: SEC
    
  slack:
    enabled: true
    webhook: ${SLACK_WEBHOOK}
    channels:
      - "#security"
      - "#devops"
      
  siem:
    type: splunk
    enabled: true
    host: splunk.example.com
    token: ${SPLUNK_TOKEN}
```

### Environment Variables

```bash
# Authentication
export DSP_GITHUB_TOKEN=your-github-token
export DSP_JIRA_TOKEN=your-jira-token
export DSP_SLACK_WEBHOOK=your-slack-webhook

# Integration Configuration
export DSP_INTEGRATION_CONFIG=path/to/config.yml
```

## Best Practices

1. **Security**
   - Use environment variables for sensitive data
   - Implement proper access controls
   - Regularly rotate API tokens

2. **Performance**
   - Use async operations where possible
   - Implement proper error handling
   - Cache results when appropriate

3. **Maintenance**
   - Keep integrations up to date
   - Monitor integration health
   - Implement proper logging

## Support

For questions and support:
- GitHub Issues: [Create an issue](https://github.com/akintunero/dsp-scanner/issues)

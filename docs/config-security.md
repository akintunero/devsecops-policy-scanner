# Configuration Security

This document provides comprehensive guidelines for securing configuration files, environment variables, and settings within the DevSecOps Policy Scanner (DSP Scanner) framework.

## Table of Contents

- [Overview](#overview)
- [Configuration File Security](#configuration-file-security)
- [Environment Variable Security](#environment-variable-security)
- [Secret Management](#secret-management)
- [Access Control](#access-control)
- [Configuration Validation](#configuration-validation)
- [Configuration Monitoring](#configuration-monitoring)
- [Security Best Practices](#security-best-practices)

## Overview

Configuration security is critical for protecting sensitive information and ensuring the DSP Scanner operates securely. This guide covers all aspects of configuration security from file permissions to secret management.

### Configuration Security Principles

- **Secure by Default**: All configurations should be secure out of the box
- **Least Privilege**: Minimal permissions and access required
- **Encryption at Rest**: Sensitive data encrypted when stored
- **Encryption in Transit**: Secure transmission of configuration data
- **Audit Trail**: Complete tracking of configuration changes

## Configuration File Security

### Secure Configuration Structure

```yaml
# config.yaml - Main configuration file
version: "2.1.0"
environment: "production"

# Security settings
security:
  # Enable secure mode
  secure_mode: true
  
  # Encryption settings
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_rotation: "30d"
    key_storage: "vault"
  
  # Access control
  access_control:
    enabled: true
    authentication: "jwt"
    authorization: "rbac"
    session_timeout: "3600s"
  
  # Audit logging
  audit:
    enabled: true
    level: "INFO"
    retention: "90d"
    encryption: true

# Scanner settings
scanner:
  # Resource limits
  resource_limits:
    cpu: "2.0"
    memory: "1Gi"
    timeout: "300s"
  
  # Sandbox settings
  sandbox:
    enabled: true
    isolation_level: "strict"
    allowed_operations: ["read", "scan", "validate"]
    blocked_operations: ["write", "network", "execute"]
  
  # Policy settings
  policies:
    validation: "strict"
    signing: "required"
    caching: "enabled"
    max_policies: 1000

# Logging configuration
logging:
  level: "INFO"
  format: "json"
  output: "file"
  file:
    path: "/var/log/dsp-scanner/"
    max_size: "100Mi"
    max_files: 10
    compression: true
  
  # Security logging
  security:
    enabled: true
    events: ["authentication", "authorization", "policy_execution"]
    alerts: true

# Network configuration
network:
  # HTTPS enforcement
  require_https: true
  verify_ssl: true
  
  # Rate limiting
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst_size: 20
  
  # Allowed endpoints
  allowed_endpoints:
    - "https://api.github.com"
    - "https://registry.npmjs.org"
    - "https://vault.company.com"
  
  # Network isolation
  isolation:
    enabled: true
    allowed_ports: [443, 80]
    blocked_ports: [22, 23, 3389]

# Storage configuration
storage:
  # Secure storage
  type: "encrypted"
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_management: "vault"
  
  # Data retention
  retention:
    scan_results: "90d"
    logs: "30d"
    temp_files: "1d"
    audit_logs: "1y"
  
  # Backup configuration
  backup:
    enabled: true
    frequency: "daily"
    encryption: true
    retention: "30d"
```

### Configuration File Permissions

```bash
# Set secure file permissions
chmod 600 config.yaml
chmod 700 .dsp/
chmod 600 .env

# Set ownership
chown dsp-scanner:dsp-scanner config.yaml
chown dsp-scanner:dsp-scanner .dsp/
chown dsp-scanner:dsp-scanner .env

# Verify permissions
ls -la config.yaml
ls -la .dsp/
ls -la .env
```

### Configuration Validation

```yaml
# Configuration schema
schema:
  type: "object"
  required: ["version", "security", "scanner"]
  properties:
    version:
      type: "string"
      pattern: "^\\d+\\.\\d+\\.\\d+$"
    
    security:
      type: "object"
      required: ["secure_mode", "encryption"]
      properties:
        secure_mode:
          type: "boolean"
          default: true
        
        encryption:
          type: "object"
          required: ["enabled", "algorithm"]
          properties:
            enabled:
              type: "boolean"
              default: true
            
            algorithm:
              type: "string"
              enum: ["AES-256-GCM", "AES-256-CBC"]
    
    scanner:
      type: "object"
      required: ["resource_limits", "sandbox"]
      properties:
        resource_limits:
          type: "object"
          properties:
            cpu:
              type: "string"
              pattern: "^\\d+(\\.\\d+)?$"
            
            memory:
              type: "string"
              pattern: "^\\d+[KMG]i$"
```

## Environment Variable Security

### Secure Environment Variables

```bash
# Production environment variables
export DSP_ENVIRONMENT="production"
export DSP_LOG_LEVEL="INFO"
export DSP_SECURE_MODE="true"

# API configuration
export DSP_API_URL="https://api.company.com"
export DSP_API_VERSION="v2"
export DSP_API_TIMEOUT="30"

# Security configuration
export DSP_ENCRYPTION_ENABLED="true"
export DSP_ENCRYPTION_ALGORITHM="AES-256-GCM"
export DSP_KEY_ROTATION_DAYS="30"

# Authentication
export DSP_AUTH_TYPE="jwt"
export DSP_JWT_SECRET="your-secure-jwt-secret"
export DSP_SESSION_TIMEOUT="3600"

# Database configuration
export DSP_DB_HOST="localhost"
export DSP_DB_PORT="5432"
export DSP_DB_NAME="dsp_scanner"
export DSP_DB_USER="dsp_user"
export DSP_DB_PASSWORD="your-secure-password"

# Network configuration
export DSP_REQUIRE_HTTPS="true"
export DSP_VERIFY_SSL="true"
export DSP_RATE_LIMIT="100"
export DSP_BURST_SIZE="20"
```

### Environment Variable Validation

```python
# Environment variable validation
import os
import re
from typing import Dict, Any

def validate_environment_variables() -> Dict[str, Any]:
    """Validate and sanitize environment variables"""
    
    # Required variables
    required_vars = [
        "DSP_ENVIRONMENT",
        "DSP_API_URL",
        "DSP_ENCRYPTION_ENABLED"
    ]
    
    # Optional variables with defaults
    optional_vars = {
        "DSP_LOG_LEVEL": "INFO",
        "DSP_SECURE_MODE": "true",
        "DSP_API_TIMEOUT": "30",
        "DSP_SESSION_TIMEOUT": "3600"
    }
    
    # Validation patterns
    patterns = {
        "DSP_ENVIRONMENT": r"^(development|staging|production)$",
        "DSP_LOG_LEVEL": r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
        "DSP_API_URL": r"^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        "DSP_API_TIMEOUT": r"^\d+$",
        "DSP_SESSION_TIMEOUT": r"^\d+$"
    }
    
    config = {}
    
    # Validate required variables
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            raise ValueError(f"Required environment variable {var} is not set")
        
        if var in patterns:
            if not re.match(patterns[var], value):
                raise ValueError(f"Invalid value for {var}: {value}")
        
        config[var] = value
    
    # Set optional variables with defaults
    for var, default in optional_vars.items():
        value = os.getenv(var, default)
        
        if var in patterns:
            if not re.match(patterns[var], value):
                raise ValueError(f"Invalid value for {var}: {value}")
        
        config[var] = value
    
    return config
```

### Environment Variable Security Checklist

```bash
# Security checklist for environment variables
echo "=== Environment Variable Security Checklist ==="

# Check for sensitive variables
echo "Checking for sensitive variables..."
env | grep -i "password\|secret\|key\|token\|credential" | wc -l

# Check for HTTPS enforcement
echo "Checking HTTPS enforcement..."
if [ "$DSP_REQUIRE_HTTPS" = "true" ]; then
    echo "✅ HTTPS enforcement enabled"
else
    echo "❌ HTTPS enforcement disabled"
fi

# Check for secure mode
echo "Checking secure mode..."
if [ "$DSP_SECURE_MODE" = "true" ]; then
    echo "✅ Secure mode enabled"
else
    echo "❌ Secure mode disabled"
fi

# Check for encryption
echo "Checking encryption settings..."
if [ "$DSP_ENCRYPTION_ENABLED" = "true" ]; then
    echo "✅ Encryption enabled"
else
    echo "❌ Encryption disabled"
fi

# Check for proper permissions
echo "Checking file permissions..."
if [ -f ".env" ]; then
    perms=$(stat -c %a .env)
    if [ "$perms" = "600" ]; then
        echo "✅ .env file has correct permissions"
    else
        echo "❌ .env file has incorrect permissions: $perms"
    fi
fi
```

## Secret Management

### Secure Secret Storage

```yaml
# Secret management configuration
secrets:
  # Vault integration
  vault:
    enabled: true
    url: "https://vault.company.com"
    auth_method: "kubernetes"
    namespace: "dsp-scanner"
    
    # Secret paths
    paths:
      api_keys: "secret/dsp-scanner/api-keys"
      database: "secret/dsp-scanner/database"
      certificates: "secret/dsp-scanner/certificates"
      encryption_keys: "secret/dsp-scanner/encryption-keys"
  
  # Local secret storage (fallback)
  local:
    enabled: false
    path: "/etc/dsp-scanner/secrets/"
    encryption: true
    permissions: "600"
  
  # Kubernetes secrets
  kubernetes:
    enabled: true
    namespace: "dsp-scanner"
    secrets:
      - name: "dsp-api-keys"
        type: "Opaque"
      - name: "dsp-database"
        type: "Opaque"
      - name: "dsp-certificates"
        type: "tls"
  
  # Rotation settings
  rotation:
    enabled: true
    frequency: "30d"
    grace_period: "7d"
    notification: true
```

### Secret Access Control

```yaml
# Secret access control
secret_access:
  # Role-based access
  roles:
    admin:
      secrets: ["*"]
      operations: ["read", "write", "rotate", "delete"]
    
    operator:
      secrets: ["api-keys", "database"]
      operations: ["read", "write"]
    
    viewer:
      secrets: ["api-keys"]
      operations: ["read"]
  
  # IP restrictions
  allowed_ips:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  
  # Time-based access
  allowed_hours:
    start: "09:00"
    end: "17:00"
  
  # Audit logging
  audit:
    enabled: true
    events: ["read", "write", "rotate", "delete"]
    retention: "1y"
```

### Secret Rotation

```bash
# Secret rotation script
#!/bin/bash

# Rotate API keys
rotate_api_keys() {
    echo "Rotating API keys..."
    
    # Generate new API key
    new_key=$(openssl rand -hex 32)
    
    # Store in Vault
    vault kv put secret/dsp-scanner/api-keys/new_key value="$new_key"
    
    # Update configuration
    dsp-scanner config --api-key "$new_key"
    
    # Remove old key after grace period
    echo "Old key will be removed after 7 days"
}

# Rotate database credentials
rotate_database_credentials() {
    echo "Rotating database credentials..."
    
    # Generate new password
    new_password=$(openssl rand -base64 32)
    
    # Update database
    psql -h localhost -U dsp_user -d dsp_scanner -c "ALTER USER dsp_user PASSWORD '$new_password';"
    
    # Store in Vault
    vault kv put secret/dsp-scanner/database/password value="$new_password"
    
    # Update configuration
    dsp-scanner config --db-password "$new_password"
}

# Rotate encryption keys
rotate_encryption_keys() {
    echo "Rotating encryption keys..."
    
    # Generate new encryption key
    new_key=$(openssl rand -hex 32)
    
    # Store in Vault
    vault kv put secret/dsp-scanner/encryption-keys/current value="$new_key"
    
    # Re-encrypt data with new key
    dsp-scanner re-encrypt --new-key "$new_key"
    
    # Archive old key
    vault kv put secret/dsp-scanner/encryption-keys/archive/$(date +%Y%m%d) value="$old_key"
}
```

## Access Control

### Configuration Access Control

```yaml
# Configuration access control
config_access:
  # File permissions
  permissions:
    config.yaml: "600"
    .env: "600"
    .dsp/: "700"
    logs/: "750"
    policies/: "750"
  
  # User and group
  ownership:
    user: "dsp-scanner"
    group: "dsp-scanner"
  
  # Access control lists
  acl:
    admin:
      files: ["*"]
      operations: ["read", "write", "delete"]
    
    operator:
      files: ["config.yaml", "logs/", "policies/"]
      operations: ["read", "write"]
    
    viewer:
      files: ["config.yaml", "logs/"]
      operations: ["read"]
  
  # Network access
  network:
    allowed_ips:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    
    allowed_hosts:
      - "admin.company.com"
      - "monitoring.company.com"
```

### Configuration Change Management

```yaml
# Configuration change management
change_management:
  # Approval workflow
  approval:
    enabled: true
    approvers:
      - "security@company.com"
      - "devops@company.com"
    
    # Change types requiring approval
    require_approval:
      - "security_settings"
      - "encryption_keys"
      - "access_control"
      - "network_settings"
  
  # Change tracking
  tracking:
    enabled: true
    git_integration: true
    changelog: "CHANGELOG.md"
    
    # Change metadata
    metadata:
      author: true
      timestamp: true
      reason: true
      impact: true
  
  # Rollback capability
  rollback:
    enabled: true
    max_versions: 10
    auto_backup: true
    verification: true
```

## Configuration Validation

### Configuration Security Validation

```python
# Configuration security validator
import yaml
import json
import re
from typing import Dict, List, Any

class ConfigSecurityValidator:
    """Validate configuration security settings"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self.load_config()
        self.issues = []
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration file"""
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def validate_security_settings(self) -> List[str]:
        """Validate security settings"""
        issues = []
        
        # Check secure mode
        if not self.config.get('security', {}).get('secure_mode', False):
            issues.append("Secure mode is disabled")
        
        # Check encryption
        if not self.config.get('security', {}).get('encryption', {}).get('enabled', False):
            issues.append("Encryption is disabled")
        
        # Check HTTPS requirement
        if not self.config.get('network', {}).get('require_https', False):
            issues.append("HTTPS is not required")
        
        # Check audit logging
        if not self.config.get('security', {}).get('audit', {}).get('enabled', False):
            issues.append("Audit logging is disabled")
        
        # Check resource limits
        resource_limits = self.config.get('scanner', {}).get('resource_limits', {})
        if not resource_limits.get('cpu') or not resource_limits.get('memory'):
            issues.append("Resource limits are not set")
        
        # Check sandbox settings
        sandbox = self.config.get('scanner', {}).get('sandbox', {})
        if not sandbox.get('enabled', False):
            issues.append("Sandbox is disabled")
        
        return issues
    
    def validate_network_security(self) -> List[str]:
        """Validate network security settings"""
        issues = []
        
        network = self.config.get('network', {})
        
        # Check SSL verification
        if not network.get('verify_ssl', False):
            issues.append("SSL verification is disabled")
        
        # Check rate limiting
        if not network.get('rate_limiting', {}).get('enabled', False):
            issues.append("Rate limiting is disabled")
        
        # Check network isolation
        if not network.get('isolation', {}).get('enabled', False):
            issues.append("Network isolation is disabled")
        
        return issues
    
    def validate_access_control(self) -> List[str]:
        """Validate access control settings"""
        issues = []
        
        access_control = self.config.get('security', {}).get('access_control', {})
        
        # Check authentication
        if not access_control.get('enabled', False):
            issues.append("Access control is disabled")
        
        # Check session timeout
        session_timeout = access_control.get('session_timeout', '0s')
        if session_timeout == '0s':
            issues.append("Session timeout is not set")
        
        return issues
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate security validation report"""
        issues = []
        issues.extend(self.validate_security_settings())
        issues.extend(self.validate_network_security())
        issues.extend(self.validate_access_control())
        
        return {
            "config_file": self.config_path,
            "timestamp": "2024-01-15T10:30:00Z",
            "total_issues": len(issues),
            "issues": issues,
            "recommendations": self.generate_recommendations(issues)
        }
    
    def generate_recommendations(self, issues: List[str]) -> List[str]:
        """Generate recommendations based on issues"""
        recommendations = []
        
        for issue in issues:
            if "Secure mode is disabled" in issue:
                recommendations.append("Enable secure mode in configuration")
            elif "Encryption is disabled" in issue:
                recommendations.append("Enable encryption for sensitive data")
            elif "HTTPS is not required" in issue:
                recommendations.append("Require HTTPS for all connections")
            elif "Audit logging is disabled" in issue:
                recommendations.append("Enable audit logging for compliance")
            elif "Resource limits are not set" in issue:
                recommendations.append("Set CPU and memory limits")
            elif "Sandbox is disabled" in issue:
                recommendations.append("Enable sandbox for policy execution")
            elif "SSL verification is disabled" in issue:
                recommendations.append("Enable SSL certificate verification")
            elif "Rate limiting is disabled" in issue:
                recommendations.append("Enable rate limiting to prevent abuse")
            elif "Network isolation is disabled" in issue:
                recommendations.append("Enable network isolation for security")
            elif "Access control is disabled" in issue:
                recommendations.append("Enable access control for authentication")
            elif "Session timeout is not set" in issue:
                recommendations.append("Set appropriate session timeout")
        
        return recommendations
```

## Configuration Monitoring

### Configuration Change Monitoring

```yaml
# Configuration monitoring
monitoring:
  # File monitoring
  file_monitoring:
    enabled: true
    files:
      - "config.yaml"
      - ".env"
      - ".dsp/"
    
    # Change detection
    detection:
      checksum: true
      modification_time: true
      size: true
    
    # Alerts
    alerts:
      on_change: true
      on_deletion: true
      on_creation: true
  
  # Configuration drift detection
  drift_detection:
    enabled: true
    baseline: "config-baseline.yaml"
    frequency: "hourly"
    tolerance: "0.1"
  
  # Configuration health checks
  health_checks:
    enabled: true
    frequency: "5m"
    checks:
      - "file_permissions"
      - "encryption_status"
      - "access_control"
      - "network_security"
      - "audit_logging"
```

### Configuration Security Monitoring

```yaml
# Security monitoring
security_monitoring:
  # Configuration tampering detection
  tampering_detection:
    enabled: true
    checksum_verification: true
    signature_verification: true
    alert_on_tampering: true
  
  # Unauthorized access detection
  unauthorized_access:
    enabled: true
    monitor_file_access: true
    monitor_config_changes: true
    alert_on_unauthorized: true
  
  # Configuration compliance monitoring
  compliance_monitoring:
    enabled: true
    frameworks:
      - "SOC2"
      - "ISO27001"
      - "NIST"
    
    # Compliance checks
    checks:
      - "encryption_enabled"
      - "access_control_enabled"
      - "audit_logging_enabled"
      - "secure_mode_enabled"
      - "https_required"
```

## Security Best Practices

### Configuration Security Checklist

#### Installation and Setup
- [ ] Use secure installation methods
- [ ] Set proper file permissions
- [ ] Configure secure defaults
- [ ] Enable encryption by default
- [ ] Set up access controls

#### Configuration Files
- [ ] Use YAML for configuration
- [ ] Validate configuration schema
- [ ] Encrypt sensitive data
- [ ] Use environment variables for secrets
- [ ] Implement configuration versioning

#### Environment Variables
- [ ] Use secure environment variables
- [ ] Validate environment variables
- [ ] Rotate secrets regularly
- [ ] Use secure secret storage
- [ ] Monitor for exposed secrets

#### Access Control
- [ ] Implement role-based access
- [ ] Use least privilege principle
- [ ] Monitor access attempts
- [ ] Implement session management
- [ ] Use secure authentication

#### Network Security
- [ ] Require HTTPS connections
- [ ] Verify SSL certificates
- [ ] Implement rate limiting
- [ ] Use network isolation
- [ ] Monitor network traffic

#### Monitoring and Logging
- [ ] Enable comprehensive logging
- [ ] Monitor configuration changes
- [ ] Set up security alerts
- [ ] Implement audit trails
- [ ] Regular security assessments

### Security Recommendations

#### Do's ✅

- ✅ Use secure configuration defaults
- ✅ Encrypt sensitive configuration data
- ✅ Implement proper access controls
- ✅ Validate all configuration inputs
- ✅ Monitor configuration changes
- ✅ Use secure secret management
- ✅ Implement configuration versioning
- ✅ Regular security assessments
- ✅ Follow security standards
- ✅ Document security decisions

#### Don'ts ❌

- ❌ Store secrets in plain text
- ❌ Use default configurations
- ❌ Skip configuration validation
- ❌ Ignore security warnings
- ❌ Use weak authentication
- ❌ Disable security features
- ❌ Skip monitoring and logging
- ❌ Ignore compliance requirements
- ❌ Use insecure protocols
- ❌ Skip regular updates

## Resources

### Documentation

- [Security Best Practices](security.md)
- [Policy Security Guidelines](policy-security.md)
- [API Documentation](api.md)
- [Deployment Guide](deployment.md)

### Tools

- [Configuration Validator](https://github.com/akintunero/devsecops-policy-scanner/tools/validator)
- [Secret Manager](https://github.com/akintunero/devsecops-policy-scanner/tools/secrets)
- [Configuration Monitor](https://github.com/akintunero/devsecops-policy-scanner/tools/monitor)

### Support

- [Security Contact](mailto:akintunero101@gmail.com)
- [Configuration Issues](https://github.com/akintunero/devsecops-policy-scanner/issues)
- [Security Advisories](https://github.com/akintunero/devsecops-policy-scanner/security/advisories) 
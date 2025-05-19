# Changelog

All notable changes to **DSP Scanner** will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org) and follows the format defined by [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2025-02-18

🎉 **First official production release**

### ➕ Added
- Initial release of **DSP Scanner**, a DevSecOps Policy Scanner designed for modern CI/CD and Cloud-Native environments
- Core security scanning engines for:
  - **Docker**
  - **Kubernetes**
  - **Terraform**
  - **Helm**
- AI/ML-powered analysis features:
  - Zero-day pattern recognition
  - Risk scoring and anomaly detection
- Policy engine support:
  - **OPA (Open Policy Agent)** integration
  - Hierarchical and customizable policy definitions
- DevSecOps integrations:
  - CI/CD pipelines (GitHub Actions, GitLab CI)
  - Major cloud providers (AWS, GCP)
  - SIEM support (Splunk, ELK)
- CLI tool with commands:
  - `scan`, `report`, `validate`, `train`
- Reporting framework:
  - JSON, SARIF, and Markdown outputs
  - Compliance tagging (NIST, CIS, OWASP)
- Documentation:
  - CLI Usage Guide
  - Developer Onboarding
  - Integration Setup
  - Contribution Workflow

### 🔐 Security
- Input sanitization for config and external files
- Isolated scanner runtime (Docker sandbox)
- Secured secrets handling with `.env` and Kubernetes Secrets
- Token-based authentication and basic RBAC
- Dependency scanning using `pip-audit`
- Secure CI/CD pipelines with linting and static analysis
- Official [SECURITY.md](SECURITY.md) policy

---

## 🔁 Versioning Policy

Follows [Semantic Versioning](https://semver.org):

- **MAJOR** – Incompatible API changes
- **MINOR** – Backward-compatible features
- **PATCH** – Bug fixes and documentation updates

---

## 📄 License

Licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

We welcome contributors! See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).


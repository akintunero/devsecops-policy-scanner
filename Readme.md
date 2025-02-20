#  DevSecOps Policy Scanner  
 **Automate Security Policy Compliance in CI/CD Pipelines**  

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)  

##  Overview  
The **DevSecOps Policy Scanner** is a CLI tool and GitHub App that scans infrastructure configurations, CI/CD settings, and repositories to enforce security policies **as code** before deployment.  

##  Key Features  
-  **Scan CI/CD Pipelines** for security misconfigurations.  
-  **Apply Security Benchmarks** (CIS, NIST, OWASP).  
-  **GitHub App Integration** for automated PR checks.  
-  **Policy-as-Code** management using YAML or JSON.  
-  **CLI Tool** for local testing before pushing to Git.  

##  Tech Stack  
- **Python** + Click (for the CLI tool).  
- **YAML-based** Policy Definitions.  
- **GitHub Actions / GitLab CI/CD** (for pipeline scanning).  


##   Use Cases  
-  Ensure **secrets aren’t exposed** in GitHub Actions.  
-  Enforce **2FA for repository admins**.  
-  Require **code scanning** in CI/CD.  

---

##  Setup & Installation  

### 1. **Clone the Repository**  
```
git clone https://github.com/akintunero/devsecops-policy-scanner.git
cd devsecops-policy-scanner
```
### 2. **Install Dependencies**  
```
pip install -r requirements.txt
```
### 3. **Run the Policy Scanner** 

```
python3 src/policy_checker.py
```
## Define Custom Policies
Security policies are defined in **YAML format** inside `policies/security.yaml`.

- Example:
```
- key: enforce_2fa
  value: true
  description: "Two-Factor Authentication (2FA) must be enabled for all repository admins."
```

##   Automate with GitHub Actions  

This scanner can run automatically **on every pull request** using **GitHub Actions**.  

###  GitHub Actions Workflow (`.github/workflows/policy_scan.yml`)  
```
name: Policy Compliance Scan
on: pull_request

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.8'

      - name: Install Dependencies
        run: pip install pyyaml

      - name: Run Policy Scanner
        run: python src/policy_checker.py
```

Deploy with Docker  

You can run the scanner inside a **Docker container**:  

###  Build the Docker Image  
```
docker build -t policy-scanner .
```
### Run the Container

```
docker run --rm policy-scanner
```

### Contributing

- Contributions are welcomed on this project by forking the repository and creating a `feature-branch`



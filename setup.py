#!/usr/bin/env python3
"""
Setup script for DevSecOps Policy Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "Readme.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "DevSecOps Policy Scanner - Advanced Security Policy Compliance Tool"

# Read requirements
def read_requirements(filename):
    requirements_path = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []

setup(
    name="devsecops-policy-scanner",
    version="2.1.0",
    author="Olúmáyòwá Akinkuehinmi",
    author_email="akintunero101@gmail.com",
    description="Advanced DevSecOps Policy Scanner for Security Compliance",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/akintunero/devsecops-policy-scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "dev": read_requirements("requirements-dev.txt"),
    },
    entry_points={
        "console_scripts": [
            "dsp-scanner=dsp_scanner.cli:app",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="security, compliance, devsecops, policy, scanning, kubernetes, docker",
    project_urls={
        "Bug Reports": "https://github.com/akintunero/devsecops-policy-scanner/issues",
        "Source": "https://github.com/akintunero/devsecops-policy-scanner",
        "Documentation": "https://github.com/akintunero/devsecops-policy-scanner#readme",
    },
) 
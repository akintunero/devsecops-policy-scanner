# Multi-stage build for DevSecOps Policy Scanner
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash scanner && \
    chown -R scanner:scanner /app
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose port for web interface (if needed)
EXPOSE 8080

# Default command
ENTRYPOINT ["python", "-m", "src.dsp_scanner.cli"]
CMD ["--help"]

# Production stage
FROM base as production

# Install production-specific dependencies
RUN pip install --no-cache-dir gunicorn

# Copy production configuration
COPY config/production.yaml ./config/

# Set production environment
ENV ENVIRONMENT=production
ENV LOG_LEVEL=INFO

# Production command
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--timeout", "120", "src.dsp_scanner.web:app"]

# Development stage
FROM base as development

# Install development tools
RUN pip install --no-cache-dir \
    ipython \
    ipdb \
    pytest-watch \
    black \
    flake8

# Set development environment
ENV ENVIRONMENT=development
ENV LOG_LEVEL=DEBUG

# Development command
CMD ["python", "-m", "src.dsp_scanner.cli", "--debug"]

# Testing stage
FROM base as testing

# Install testing dependencies
RUN pip install --no-cache-dir \
    pytest-cov \
    pytest-mock \
    pytest-asyncio \
    coverage

# Set testing environment
ENV ENVIRONMENT=testing
ENV LOG_LEVEL=DEBUG

# Testing command
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=html"]

# Security scanning stage
FROM base as security

# Install security tools
RUN pip install --no-cache-dir \
    bandit \
    safety \
    pip-audit

# Security scanning command
CMD ["bandit", "-r", "src/", "-f", "json", "-o", "bandit-report.json"]

# Documentation stage
FROM base as docs

# Install documentation tools
RUN pip install --no-cache-dir \
    sphinx \
    sphinx-rtd-theme \
    myst-parser

# Build documentation
RUN sphinx-build -b html docs/ docs/_build/html

# Serve documentation
CMD ["python", "-m", "http.server", "8000", "-d", "docs/_build/html"]

# Alpine version for smaller image
FROM python:3.11-alpine as alpine

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apk add --no-cache \
    curl \
    wget \
    git \
    build-base

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN adduser -D scanner && \
    chown -R scanner:scanner /app
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "src.dsp_scanner.cli"]
CMD ["--help"]

# Labels for better image management
LABEL maintainer="Olúmáyòwá Akinkuehinmi <akintunero101@gmail.com>"
LABEL version="2.1.0"
LABEL description="DevSecOps Policy Scanner - Advanced security policy scanning and compliance checking"
LABEL org.opencontainers.image.source="https://github.com/akintunero/devsecops-policy-scanner"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Olúmáyòwá Akinkuehinmi <akintunero101@gmail.com>"

# Metadata
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.version="2.1.0"

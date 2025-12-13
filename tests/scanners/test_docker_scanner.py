"""
Tests for the Docker security scanner.
"""

from pathlib import Path
from unittest.mock import Mock

import pytest

from dsp_scanner.core.policy import Policy
from dsp_scanner.core.results import Severity
from dsp_scanner.scanners.docker import DockerScanner


@pytest.fixture
def scanner():
    """Create a Docker scanner instance for testing."""
    return DockerScanner()


@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test policy"
    policy.platform = "docker"
    policy.severity = "high"
    return policy


def create_dockerfile(tmp_path: Path, content: str) -> Path:
    """Helper to create a test Dockerfile."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(content)
    return dockerfile


def create_compose_file(tmp_path: Path, content: str) -> Path:
    """Helper to create a test docker-compose.yml file."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(content)
    return compose_file


@pytest.mark.asyncio
async def test_scan_basic_dockerfile(scanner, tmp_path):
    """Test scanning a basic Dockerfile."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM python:3.9
    WORKDIR /app
    COPY . .
    RUN pip install -r requirements.txt
    CMD ["python", "app.py"]
    """,
    )

    result = await scanner.scan(dockerfile)

    assert result.findings
    assert any(f.id == "DOCKER001" for f in result.findings)  # Latest tag warning
    assert result.metrics["total_files_scanned"] == 1


@pytest.mark.asyncio
async def test_scan_dockerfile_with_security_issues(scanner, tmp_path):
    """Test scanning a Dockerfile with multiple security issues."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM python:latest
    RUN apt-get update && apt-get install -y nginx
    EXPOSE 22
    USER root
    ENV PASSWORD=mysecret
    RUN curl http://example.com/script.sh | bash
    """,
    )

    result = await scanner.scan(dockerfile)

    # Verify findings
    findings = result.findings
    assert any(f.id == "DOCKER001" for f in findings)  # Latest tag
    assert any(f.id == "DOCKER003" for f in findings)  # Root user
    assert any(f.id == "DOCKER005" for f in findings)  # Sensitive data
    assert any(f.severity == Severity.HIGH for f in findings)


@pytest.mark.asyncio
async def test_scan_dockerfile_with_best_practices(scanner, tmp_path):
    """Test scanning a Dockerfile that follows best practices."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM python:3.9-slim
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    COPY . .
    RUN useradd -m appuser
    USER appuser
    EXPOSE 8000
    HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health
    CMD ["python", "app.py"]
    """,
    )

    result = await scanner.scan(dockerfile)

    # Should have minimal or no findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
async def test_scan_compose_file(scanner, tmp_path):
    """Test scanning a docker-compose.yml file."""
    compose_file = create_compose_file(
        tmp_path,
        """
    version: '3.8'
    services:
      web:
        build: .
        ports:
          - "0.0.0.0:80:80"
        privileged: true
      db:
        image: postgres:latest
        environment:
          POSTGRES_PASSWORD: secret
    """,
    )

    result = await scanner.scan(compose_file)

    # Verify findings
    findings = result.findings
    assert any(f.id == "DOCKER009" for f in findings)  # Privileged mode
    assert any(f.id == "DOCKER010" for f in findings)  # Exposed ports
    assert any("POSTGRES_PASSWORD" in f.description for f in findings)


@pytest.mark.asyncio
async def test_scan_with_custom_policy(scanner, tmp_path, mock_policy):
    """Test scanning with a custom policy."""
    dockerfile = create_dockerfile(tmp_path, "FROM python:3.9")

    # Setup mock policy evaluation
    mock_policy.evaluate.return_value = {
        "violations": [
            {
                "title": "Custom Policy Violation",
                "description": "Test violation",
                "severity": "high",
            }
        ]
    }

    result = await scanner.scan(dockerfile, policies=[mock_policy])

    assert any(f.id.startswith("POLICY_") for f in result.findings)
    mock_policy.evaluate.assert_called_once()


@pytest.mark.asyncio
async def test_scan_multiple_files(scanner, tmp_path):
    """Test scanning multiple Docker-related files."""
    # Create Dockerfile
    create_dockerfile(tmp_path, "FROM python:3.9")

    # Create docker-compose.yml
    create_compose_file(
        tmp_path,
        """
    version: '3.8'
    services:
      web:
        build: .
    """,
    )

    # Create another Dockerfile in subdirectory
    subdir = tmp_path / "service"
    subdir.mkdir()
    create_dockerfile(subdir, "FROM node:latest")

    result = await scanner.scan(tmp_path)

    assert result.metrics["total_files_scanned"] == 3
    assert any("node:latest" in f.code_snippet for f in result.findings)


@pytest.mark.asyncio
async def test_scan_package_management(scanner, tmp_path):
    """Test scanning package management practices."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM ubuntu:20.04
    RUN apt-get install nginx
    RUN apt-get update && apt-get install -y python3
    """,
    )

    result = await scanner.scan(dockerfile)

    assert any(f.id == "DOCKER006" for f in result.findings)  # Missing apt-get update
    assert any(f.id == "DOCKER007" for f in result.findings)  # Version not pinned


@pytest.mark.asyncio
async def test_scan_healthcheck(scanner, tmp_path):
    """Test scanning for HEALTHCHECK instruction."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM python:3.9
    COPY . .
    CMD ["python", "app.py"]
    """,
    )

    result = await scanner.scan(dockerfile)

    assert any(f.id == "DOCKER008" for f in result.findings)  # Missing HEALTHCHECK


@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Test scanner error handling."""
    with pytest.raises(FileNotFoundError):
        await scanner.scan(Path("/nonexistent/Dockerfile"))


def test_is_dockerfile():
    """Test Dockerfile detection."""
    assert DockerScanner._is_dockerfile(Path("Dockerfile"))
    assert DockerScanner._is_dockerfile(Path("service.dockerfile"))
    assert DockerScanner._is_dockerfile(Path("web.Dockerfile"))
    assert not DockerScanner._is_dockerfile(Path("dockerfile.txt"))


def test_is_compose_file():
    """Test docker-compose file detection."""
    assert DockerScanner._is_compose_file(Path("docker-compose.yml"))
    assert DockerScanner._is_compose_file(Path("docker-compose.yaml"))
    assert not DockerScanner._is_compose_file(Path("compose.txt"))


@pytest.mark.asyncio
async def test_scan_multistage_dockerfile(scanner, tmp_path):
    """Test scanning multi-stage Dockerfile."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM node:14 AS builder
    WORKDIR /app
    COPY . .
    RUN npm install && npm run build

    FROM nginx:alpine
    COPY --from=builder /app/build /usr/share/nginx/html
    EXPOSE 80
    """,
    )

    result = await scanner.scan(dockerfile)

    # Should detect issues in both stages
    assert any("node:14" in f.code_snippet for f in result.findings)
    assert any("nginx:alpine" in f.code_snippet for f in result.findings)


@pytest.mark.asyncio
async def test_scan_environment_variables(scanner, tmp_path):
    """Test scanning environment variables for sensitive data."""
    dockerfile = create_dockerfile(
        tmp_path,
        """
    FROM python:3.9
    ENV API_KEY=12345
    ENV DEBUG=true
    ENV APP_TOKEN=secret
    """,
    )

    result = await scanner.scan(dockerfile)

    assert any("API_KEY" in f.description for f in result.findings)
    assert any("APP_TOKEN" in f.description for f in result.findings)
    assert not any("DEBUG" in f.description for f in result.findings)

# Use multi-stage build for smaller final image
FROM python:3.9-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY src/ ./src/
COPY README.md ./

# Build project
RUN ~/.local/bin/poetry config virtualenvs.create false \
    && ~/.local/bin/poetry install --no-dev --no-interaction --no-ansi

# Final stage
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy built package from builder
COPY --from=builder /app /app
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# Create non-root user
RUN useradd -m -u 1000 scanner
USER scanner

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PATH="/home/scanner/.local/bin:${PATH}"

# Create directory for reports
RUN mkdir -p /home/scanner/reports

# Set entrypoint
ENTRYPOINT ["dsp-scanner"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="DSP Scanner"
LABEL org.opencontainers.image.description="Advanced DevSecOps Policy Scanner"
LABEL org.opencontainers.image.source="https://github.com/yourusername/dsp-scanner"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="DSP Scanner Team"
LABEL org.opencontainers.image.authors="Your Name <your.email@example.com>"

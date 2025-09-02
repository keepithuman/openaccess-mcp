# Multi-stage build for OpenAccess MCP Server
FROM python:3.12-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY pyproject.toml .
COPY README.md .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir .

# Production stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    wireguard-tools \
    openvpn \
    xrdp \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r openaccess && useradd -r -g openaccess openaccess

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create necessary directories
RUN mkdir -p /app/profiles /app/secrets /app/audit /app/logs \
    && chown -R openaccess:openaccess /app

# Switch to non-root user
USER openaccess

# Set working directory
WORKDIR /app

# Expose MCP port (default 8000)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import openaccess_mcp; print('OK')" || exit 1

# Default command
CMD ["openaccess-mcp", "serve", "--host", "0.0.0.0", "--port", "8000"]

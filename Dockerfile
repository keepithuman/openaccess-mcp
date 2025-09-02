FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

# Copy source code
COPY openaccess_mcp/ ./openaccess_mcp/

# Create directories for profiles and secrets
RUN mkdir -p /app/profiles /app/secrets /app/audit

# Create non-root user
RUN useradd -m -u 1000 openaccess && \
    chown -R openaccess:openaccess /app

# Switch to non-root user
USER openaccess

# Expose port (if needed for future HTTP mode)
EXPOSE 8080

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import openaccess_mcp; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "openaccess_mcp.server"]

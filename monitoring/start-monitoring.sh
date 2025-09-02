#!/bin/bash

# OpenAccess MCP Monitoring Stack Quick Start
# This script sets up and starts the complete monitoring stack

set -e

echo "🚀 Starting OpenAccess MCP Monitoring Stack..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install it and try again."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p grafana/dashboards
mkdir -p grafana/provisioning/datasources
mkdir -p rules

# Copy configuration files if they don't exist
if [ ! -f "prometheus.yml" ]; then
    echo "❌ prometheus.yml not found. Please ensure you're in the monitoring directory."
    exit 1
fi

# Start the monitoring stack
echo "🐳 Starting monitoring services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service status
echo "🔍 Checking service status..."
docker-compose ps

# Display access information
echo ""
echo "✅ Monitoring stack is running!"
echo ""
echo "📊 Access your monitoring tools:"
echo "   • Prometheus: http://localhost:9090"
echo "   • Grafana:    http://localhost:3000 (admin/admin123)"
echo "   • Alertmanager: http://localhost:9093"
echo ""
echo "📋 Next steps:"
echo "   1. Open Grafana at http://localhost:3000"
echo "   2. Login with admin/admin123"
echo "   3. Import the dashboard: grafana/dashboards/openaccess-mcp-overview.json"
echo "   4. Configure your OpenAccess MCP server to expose metrics at /metrics"
echo ""
echo "🛑 To stop the monitoring stack:"
echo "   docker-compose down"
echo ""
echo "📚 For more information, see MONITORING.md"

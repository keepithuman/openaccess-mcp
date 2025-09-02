# OpenAccess MCP Deployment Guide

This guide covers deploying the OpenAccess MCP server using various containerization and orchestration technologies.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Deployment](#docker-deployment)
3. [Docker Compose Deployment](#docker-compose-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Production Considerations](#production-considerations)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker 20.10+ or Docker Desktop
- Docker Compose 2.0+ (for multi-service deployment)
- Kubernetes 1.24+ (for K8s deployment)
- OpenSSH client tools
- WireGuard tools (for VPN functionality)
- XRDP (for RDP functionality)

## Docker Deployment

### Quick Start

```bash
# Build the image
docker build -t openaccess-mcp:0.0.1 .

# Run the container
docker run -d \
  --name openaccess-mcp \
  -p 8000:8000 \
  -v $(pwd)/profiles:/app/profiles:ro \
  -v $(pwd)/secrets:/app/secrets:ro \
  -v $(pwd)/audit:/app/audit \
  -v $(pwd)/logs:/app/logs \
  openaccess-mcp:0.0.1
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_HOST` | `0.0.0.0` | Host to bind the MCP server to |
| `MCP_PORT` | `8000` | Port to bind the MCP server to |
| `PROFILES_DIR` | `/app/profiles` | Directory containing profile configurations |
| `SECRETS_DIR` | `/app/secrets` | Directory containing secret files |
| `AUDIT_LOG_PATH` | `/app/audit/audit.log` | Path to audit log file |
| `AUDIT_KEY_PATH` | `/app/audit/audit.key` | Path to audit signing key |

### Volume Mounts

- **`/app/profiles`**: Profile configurations (read-only)
- **`/app/secrets`**: Secret files (read-only)
- **`/app/audit`**: Audit logs and signing keys
- **`/app/logs`**: Application logs

## Docker Compose Deployment

### Quick Start

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f openaccess-mcp

# Stop all services
docker-compose down
```

### Services

1. **openaccess-mcp**: Main MCP server
2. **redis**: Caching and session management (optional)
3. **postgres**: Database for audit logs and user management (optional)
4. **nginx**: Reverse proxy with SSL termination (optional)

### Configuration

Edit `docker-compose.yml` to customize:
- Port mappings
- Volume mounts
- Environment variables
- Resource limits
- Health checks

### SSL Setup

1. Generate SSL certificates:
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key \
  -out nginx/ssl/server.crt
```

2. Update `nginx/nginx.conf` with your domain
3. Restart the nginx service

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Helm 3.0+ (optional)
- cert-manager (for SSL certificates)

### Quick Start

```bash
# Apply the deployment
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=openaccess-mcp

# View logs
kubectl logs -l app=openaccess-mcp -f

# Access the service
kubectl port-forward svc/openaccess-mcp-service 8000:8000
```

### Components

- **Deployment**: 3 replicas with rolling updates
- **Service**: ClusterIP for internal communication
- **Ingress**: External access with SSL termination
- **ConfigMap**: Profile configurations
- **Secrets**: Database passwords and sensitive data
- **PVCs**: Persistent storage for audit logs and logs
- **RBAC**: Service account and permissions

### Customization

1. **Update domain**: Change `openaccess-mcp.example.com` in ingress
2. **Adjust resources**: Modify CPU/memory limits in deployment
3. **Add profiles**: Update the ConfigMap with your profiles
4. **Configure secrets**: Update the Secret with your credentials

## Production Considerations

### High Availability

- **Multiple replicas**: Use 3+ replicas for redundancy
- **Load balancing**: Use a load balancer or ingress controller
- **Health checks**: Implement proper liveness/readiness probes
- **Auto-scaling**: Configure HPA for dynamic scaling

### Security

- **Network policies**: Restrict pod-to-pod communication
- **RBAC**: Use least-privilege service accounts
- **Secrets management**: Use external secret managers (Vault, AWS Secrets Manager)
- **Pod security**: Enable Pod Security Standards
- **Network security**: Use mTLS for service-to-service communication

### Performance

- **Resource limits**: Set appropriate CPU/memory limits
- **Connection pooling**: Use Redis for session management
- **Caching**: Implement response caching where appropriate
- **Monitoring**: Use Prometheus and Grafana for metrics

### Backup and Recovery

- **Audit logs**: Backup audit logs regularly
- **Profiles**: Version control profile configurations
- **Secrets**: Backup secret configurations
- **Disaster recovery**: Test recovery procedures

## Monitoring and Logging

### Metrics

The server exposes metrics at `/metrics` endpoint:
- Request counts and latencies
- Error rates
- Resource usage
- Connection counts

### Logging

- **Application logs**: Structured logging with correlation IDs
- **Audit logs**: Immutable audit trail with cryptographic signatures
- **Access logs**: HTTP request/response logging
- **Error logs**: Detailed error information with stack traces

### Monitoring Stack

```yaml
# Example Prometheus configuration
scrape_configs:
  - job_name: 'openaccess-mcp'
    static_configs:
      - targets: ['openaccess-mcp:8000']
    metrics_path: /metrics
    scrape_interval: 15s
```

## Security Best Practices

### Authentication

- Use strong authentication mechanisms
- Implement role-based access control (RBAC)
- Use JWT tokens with short expiration
- Implement multi-factor authentication (MFA)

### Network Security

- Use TLS 1.3 for all communications
- Implement network segmentation
- Use VPNs for remote access
- Monitor network traffic for anomalies

### Data Protection

- Encrypt data at rest and in transit
- Implement proper key management
- Use secure secret storage
- Regular security audits

### Compliance

- Maintain audit trails
- Implement data retention policies
- Regular security assessments
- Compliance monitoring and reporting

## Troubleshooting

### Common Issues

1. **Container won't start**
   - Check resource limits
   - Verify volume mounts
   - Check environment variables

2. **Connection refused**
   - Verify port mappings
   - Check firewall rules
   - Verify service configuration

3. **Authentication failures**
   - Check secret configurations
   - Verify profile settings
   - Check audit logs

4. **Performance issues**
   - Monitor resource usage
   - Check connection pooling
   - Review caching configuration

### Debug Commands

```bash
# Check container logs
docker logs openaccess-mcp

# Inspect container
docker inspect openaccess-mcp

# Execute commands in container
docker exec -it openaccess-mcp /bin/bash

# Check resource usage
docker stats openaccess-mcp
```

### Support

For additional support:
- Check the [README.md](README.md) for usage examples
- Review the [API documentation](API.md)
- Open an issue on GitHub
- Check the [troubleshooting guide](TROUBLESHOOTING.md)

## Next Steps

1. **Customize profiles**: Configure your server profiles
2. **Set up monitoring**: Implement monitoring and alerting
3. **Configure backups**: Set up automated backup procedures
4. **Security review**: Conduct security assessment
5. **Performance tuning**: Optimize based on usage patterns
6. **Documentation**: Document your deployment configuration

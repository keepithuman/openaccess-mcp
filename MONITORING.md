# OpenAccess MCP Monitoring Setup Guide

This guide covers setting up comprehensive monitoring for your OpenAccess MCP server using Prometheus, Grafana, and Alertmanager.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Metrics](#metrics)
6. [Dashboards](#dashboards)
7. [Alerting](#alerting)
8. [Production Deployment](#production-deployment)
9. [Troubleshooting](#troubleshooting)

## Overview

The monitoring stack provides:

- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Alertmanager**: Alert routing and notification
- **Node Exporter**: System metrics
- **Custom Metrics**: OpenAccess MCP specific metrics

## Prerequisites

- Docker and Docker Compose
- OpenAccess MCP server running
- Basic understanding of Prometheus and Grafana

## Quick Start

### 1. Start the Monitoring Stack

```bash
cd monitoring
docker-compose up -d
```

### 2. Access the Services

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin123)
- **Alertmanager**: http://localhost:9093

### 3. Import Dashboard

1. Open Grafana (http://localhost:3000)
2. Login with `admin/admin123`
3. Go to Dashboards → Import
4. Upload `grafana/dashboards/openaccess-mcp-overview.json`

## Configuration

### Prometheus Configuration

The main configuration is in `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'openaccess-mcp'
    static_configs:
      - targets: ['openaccess-mcp:8000']
    metrics_path: /metrics
    scrape_interval: 10s
```

### Recording Rules

Pre-computed metrics in `rules/recording_rules.yml`:

```yaml
- record: openaccess_mcp_overall_success_rate
  expr: |
    rate(openaccess_mcp_ssh_operations_total{result="success"}[5m]) /
    rate(openaccess_mcp_ssh_operations_total[5m])
```

### Alerting Rules

Alerts in `rules/alerting_rules.yml`:

```yaml
- alert: HighErrorRate
  expr: openaccess_mcp_overall_success_rate < 0.95
  for: 5m
  labels:
    severity: warning
```

## Metrics

### Available Metrics

#### Operation Counters
- `openaccess_mcp_ssh_operations_total`
- `openaccess_mcp_sftp_operations_total`
- `openaccess_mcp_rsync_operations_total`
- `openaccess_mcp_tunnel_operations_total`
- `openaccess_mcp_vpn_operations_total`
- `openaccess_mcp_rdp_operations_total`

#### Duration Histograms
- `openaccess_mcp_ssh_operation_duration_seconds`
- `openaccess_mcp_sftp_operation_duration_seconds`
- `openaccess_mcp_rsync_operation_duration_seconds`

#### Resource Gauges
- `openaccess_mcp_active_connections`
- `openaccess_mcp_memory_bytes`
- `openaccess_mcp_memory_limit_bytes`

#### Security Metrics
- `openaccess_mcp_policy_violations_total`
- `openaccess_mcp_auth_failures_total`

### Adding Metrics to Your Code

```python
from openaccess_mcp.metrics import record_ssh_operation, record_sftp_operation

# Record SSH operation
start_time = time.time()
try:
    result = await ssh_provider.exec_command(...)
    duration = time.time() - start_time
    record_ssh_operation("success", profile_id, caller, duration)
except Exception as e:
    duration = time.time() - start_time
    record_ssh_operation("failure", profile_id, caller, duration)
```

## Dashboards

### Main Dashboard

The overview dashboard includes:

1. **Key Metrics**: Success rate, connections, memory, CPU
2. **Operations**: Per-second rates for all operations
3. **Performance**: Response time percentiles
4. **Success Rates**: By operation type
5. **Error Rates**: By operation type
6. **Cache Performance**: Hit rates and efficiency
7. **Security**: Policy violations and auth failures
8. **System Resources**: Memory, disk, network usage

### Custom Dashboards

Create custom dashboards for specific use cases:

#### Operations Dashboard
- Focus on SSH, SFTP, and Rsync operations
- Real-time performance metrics
- Error rate monitoring

#### Security Dashboard
- Policy violations over time
- Authentication failures
- Audit log statistics

#### Infrastructure Dashboard
- System resource usage
- Network I/O patterns
- Container health status

## Alerting

### Alert Severity Levels

- **Warning**: Non-critical issues requiring attention
- **Critical**: Issues requiring immediate action

### Alert Categories

1. **Performance Alerts**
   - High error rates
   - High latency
   - Low success rates

2. **Resource Alerts**
   - High memory usage
   - High CPU usage
   - Connection limits

3. **Security Alerts**
   - High policy violations
   - High auth failures
   - Unusual activity patterns

4. **Infrastructure Alerts**
   - Service down
   - High system resource usage
   - Network issues

### Alert Notifications

Configure notifications in `alertmanager.yml`:

```yaml
receivers:
  - name: 'slack-notifications'
    slack_configs:
      - channel: '#openaccess-mcp-alerts'
        title: 'OpenAccess MCP Alert'
```

### Custom Alerts

Add custom alerts for your specific needs:

```yaml
- alert: CustomAlert
  expr: your_custom_metric > threshold
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Custom alert description"
```

## Production Deployment

### High Availability

1. **Multiple Prometheus Instances**
   ```yaml
   prometheus:
     replicas: 3
     persistentVolumeClaim:
       storageClassName: fast-ssd
   ```

2. **Grafana Clustering**
   ```yaml
   grafana:
     replicas: 2
     sessionStorage:
       type: redis
   ```

3. **Alertmanager Clustering**
   ```yaml
   alertmanager:
     replicas: 3
     cluster:
       peer: "alertmanager-1:9094"
   ```

### Security

1. **Authentication**
   ```yaml
   grafana:
     security:
       adminUser: admin
       adminPassword: ${GRAFANA_ADMIN_PASSWORD}
   ```

2. **TLS/SSL**
   ```yaml
   prometheus:
     tls:
       enabled: true
       secretName: prometheus-tls
   ```

3. **Network Policies**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   spec:
     podSelector:
       matchLabels:
         app: prometheus
     policyTypes:
     - Ingress
     - Egress
   ```

### Scaling

1. **Horizontal Pod Autoscaling**
   ```yaml
   apiVersion: autoscaling/v2
   kind: HorizontalPodAutoscaler
   spec:
     minReplicas: 2
     maxReplicas: 10
     metrics:
     - type: Resource
       resource:
         name: cpu
         target:
           type: Utilization
           averageUtilization: 70
   ```

2. **Storage Scaling**
   ```yaml
   prometheus:
     storageSpec:
       volumeClaimTemplate:
         spec:
           resources:
             requests:
               storage: 100Gi
           storageClassName: fast-ssd
   ```

## Troubleshooting

### Common Issues

1. **Metrics Not Appearing**
   - Check Prometheus targets (http://localhost:9090/targets)
   - Verify metrics endpoint is accessible
   - Check scrape configuration

2. **High Memory Usage**
   - Reduce scrape interval
   - Limit retention period
   - Use recording rules

3. **Dashboard Errors**
   - Verify Prometheus datasource
   - Check metric names
   - Validate PromQL queries

### Debug Commands

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Check metrics endpoint
curl http://localhost:8000/metrics

# Check alertmanager
curl http://localhost:9093/api/v1/alerts

# View Prometheus logs
docker logs openaccess-prometheus

# View Grafana logs
docker logs openaccess-grafana
```

### Performance Tuning

1. **Prometheus**
   ```yaml
   command:
     - '--storage.tsdb.retention.time=15d'
     - '--storage.tsdb.max-block-duration=2h'
     - '--storage.tsdb.min-block-duration=15m'
   ```

2. **Grafana**
   ```yaml
   environment:
     - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/overview.json
     - GF_SERVER_ROOT_URL=http://localhost:3000
   ```

## Integration with Existing Infrastructure

### Kubernetes

```bash
# Apply monitoring stack
kubectl apply -f k8s/monitoring/

# Check status
kubectl get pods -n monitoring
kubectl get svc -n monitoring
```

### Docker Swarm

```bash
# Deploy monitoring stack
docker stack deploy -c docker-compose.yml monitoring

# Check services
docker service ls
docker service ps monitoring_prometheus
```

### Bare Metal

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvf prometheus-2.45.0.linux-amd64.tar.gz
cd prometheus-2.45.0.linux-amd64

# Start Prometheus
./prometheus --config.file=prometheus.yml
```

## Next Steps

1. **Customize Dashboards**: Modify existing dashboards for your needs
2. **Add Custom Metrics**: Implement business-specific metrics
3. **Set Up Notifications**: Configure Slack, email, or PagerDuty
4. **Performance Tuning**: Optimize for your workload
5. **Security Hardening**: Implement authentication and encryption
6. **Backup Strategy**: Set up monitoring data backup

## Support

For additional help:
- Check the [Prometheus documentation](https://prometheus.io/docs/)
- Review [Grafana documentation](https://grafana.com/docs/)
- Open an issue on GitHub
- Check the troubleshooting section above

Your OpenAccess MCP server is now fully monitored! 🚀

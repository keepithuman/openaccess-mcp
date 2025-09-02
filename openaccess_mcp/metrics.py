"""Prometheus metrics for OpenAccess MCP server."""

import time
from typing import Dict, Any
from prometheus_client import (
    Counter, Histogram, Gauge, Info, generate_latest,
    CONTENT_TYPE_LATEST
)

# Operation counters
ssh_operations_total = Counter(
    'openaccess_mcp_ssh_operations_total',
    'Total SSH operations',
    ['result', 'profile_id', 'caller']
)

sftp_operations_total = Counter(
    'openaccess_mcp_sftp_operations_total',
    'Total SFTP operations',
    ['result', 'profile_id', 'caller', 'direction']
)

rsync_operations_total = Counter(
    'openaccess_mcp_rsync_operations_total',
    'Total Rsync operations',
    ['result', 'profile_id', 'caller', 'direction']
)

tunnel_operations_total = Counter(
    'openaccess_mcp_tunnel_operations_total',
    'Total tunnel operations',
    ['result', 'profile_id', 'caller', 'tunnel_type']
)

vpn_operations_total = Counter(
    'openaccess_mcp_vpn_operations_total',
    'Total VPN operations',
    ['result', 'profile_id', 'caller', 'action']
)

rdp_operations_total = Counter(
    'openaccess_mcp_rdp_operations_total',
    'Total RDP operations',
    ['result', 'profile_id', 'caller']
)

# Operation duration histograms
ssh_operation_duration_seconds = Histogram(
    'openaccess_mcp_ssh_operation_duration_seconds',
    'SSH operation duration in seconds',
    ['profile_id', 'caller'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

sftp_operation_duration_seconds = Histogram(
    'openaccess_mcp_sftp_operation_duration_seconds',
    'SFTP operation duration in seconds',
    ['profile_id', 'caller', 'direction'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

rsync_operation_duration_seconds = Histogram(
    'openaccess_mcp_rsync_operation_duration_seconds',
    'Rsync operation duration in seconds',
    ['profile_id', 'caller', 'direction'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

tunnel_operation_duration_seconds = Histogram(
    'openaccess_mcp_tunnel_operation_duration_seconds',
    'Tunnel operation duration in seconds',
    ['profile_id', 'caller', 'tunnel_type'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

vpn_operation_duration_seconds = Histogram(
    'openaccess_mcp_vpn_operation_duration_seconds',
    'VPN operation duration in seconds',
    ['profile_id', 'caller', 'action'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

rdp_operation_duration_seconds = Histogram(
    'openaccess_mcp_rdp_operation_duration_seconds',
    'RDP operation duration in seconds',
    ['profile_id', 'caller'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

# Resource usage gauges
active_connections = Gauge(
    'openaccess_mcp_active_connections',
    'Number of active connections',
    ['profile_id', 'protocol']
)

memory_bytes = Gauge(
    'openaccess_mcp_memory_bytes',
    'Memory usage in bytes'
)

memory_limit_bytes = Gauge(
    'openaccess_mcp_memory_limit_bytes',
    'Memory limit in bytes'
)

cpu_seconds_total = Counter(
    'openaccess_mcp_cpu_seconds_total',
    'Total CPU time in seconds'
)

# Cache metrics
cache_hits_total = Counter(
    'openaccess_mcp_cache_hits_total',
    'Total cache hits'
)

cache_misses_total = Counter(
    'openaccess_mcp_cache_misses_total',
    'Total cache misses'
)

cache_size = Gauge(
    'openaccess_mcp_cache_size',
    'Current cache size'
)

# Security metrics
policy_violations_total = Counter(
    'openaccess_mcp_policy_violations_total',
    'Total policy violations',
    ['profile_id', 'caller', 'reason']
)

auth_failures_total = Counter(
    'openaccess_mcp_auth_failures_total',
    'Total authentication failures',
    ['profile_id', 'caller', 'reason']
)

# Audit metrics
audit_log_entries_total = Counter(
    'openaccess_mcp_audit_log_entries_total',
    'Total audit log entries',
    ['result', 'tool', 'profile_id']
)

# Server info
server_info = Info(
    'openaccess_mcp_server',
    'OpenAccess MCP server information'
)

def record_ssh_operation(result: str, profile_id: str, caller: str, duration: float):
    """Record SSH operation metrics."""
    ssh_operations_total.labels(result=result, profile_id=profile_id, caller=caller).inc()
    ssh_operation_duration_seconds.labels(profile_id=profile_id, caller=caller).observe(duration)

def record_sftp_operation(result: str, profile_id: str, caller: str, direction: str, duration: float):
    """Record SFTP operation metrics."""
    sftp_operations_total.labels(result=result, profile_id=profile_id, caller=caller, direction=direction).inc()
    sftp_operation_duration_seconds.labels(profile_id=profile_id, caller=caller, direction=direction).observe(duration)

def record_rsync_operation(result: str, profile_id: str, caller: str, direction: str, duration: float):
    """Record Rsync operation metrics."""
    rsync_operations_total.labels(result=result, profile_id=profile_id, caller=caller, direction=direction).inc()
    rsync_operation_duration_seconds.labels(profile_id=profile_id, caller=caller, direction=direction).observe(duration)

def record_tunnel_operation(result: str, profile_id: str, caller: str, tunnel_type: str, duration: float):
    """Record tunnel operation metrics."""
    tunnel_operations_total.labels(result=result, profile_id=profile_id, caller=caller, tunnel_type=tunnel_type).inc()
    tunnel_operation_duration_seconds.labels(profile_id=profile_id, caller=caller, tunnel_type=tunnel_type).observe(duration)

def record_vpn_operation(result: str, profile_id: str, caller: str, action: str, duration: float):
    """Record VPN operation metrics."""
    vpn_operations_total.labels(result=result, profile_id=profile_id, caller=caller, action=action).inc()
    vpn_operation_duration_seconds.labels(profile_id=profile_id, caller=caller, action=action).observe(duration)

def record_rdp_operation(result: str, profile_id: str, caller: str, duration: float):
    """Record RDP operation metrics."""
    rdp_operations_total.labels(result=result, profile_id=profile_id, caller=caller).inc()
    rdp_operation_duration_seconds.labels(profile_id=profile_id, caller=caller).observe(duration)

def set_active_connections(profile_id: str, protocol: str, count: int):
    """Set active connections count."""
    active_connections.labels(profile_id=profile_id, protocol=protocol).set(count)

def set_memory_usage(bytes_used: int, bytes_limit: int):
    """Set memory usage metrics."""
    memory_bytes.set(bytes_used)
    memory_limit_bytes.set(bytes_limit)

def increment_cpu_time(seconds: float):
    """Increment CPU time counter."""
    cpu_seconds_total.inc(seconds)

def record_cache_hit():
    """Record a cache hit."""
    cache_hits_total.inc()

def record_cache_miss():
    """Record a cache miss."""
    cache_misses_total.inc()

def set_cache_size(size: int):
    """Set current cache size."""
    cache_size.set(size)

def record_policy_violation(profile_id: str, caller: str, reason: str):
    """Record a policy violation."""
    policy_violations_total.labels(profile_id=profile_id, caller=caller, reason=reason).inc()

def record_auth_failure(profile_id: str, caller: str, reason: str):
    """Record an authentication failure."""
    auth_failures_total.labels(profile_id=profile_id, caller=caller, reason=reason).inc()

def record_audit_log_entry(result: str, tool: str, profile_id: str):
    """Record an audit log entry."""
    audit_log_entries_total.labels(result=result, tool=tool, profile_id=profile_id).inc()

def set_server_info(version: str, build_date: str):
    """Set server information."""
    server_info.info({'version': version, 'build_date': build_date})

def get_metrics():
    """Get Prometheus metrics."""
    return generate_latest()

def get_metrics_content_type():
    """Get Prometheus metrics content type."""
    return CONTENT_TYPE_LATEST

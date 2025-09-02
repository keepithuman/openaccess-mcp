# OpenAccess MCP API Documentation

This document provides comprehensive API documentation for the OpenAccess MCP server, including all available tools, providers, and endpoints.

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Core Concepts](#core-concepts)
4. [SSH Provider](#ssh-provider)
5. [SFTP Provider](#sftp-provider)
6. [Rsync Provider](#rsync-provider)
7. [Tunnel Provider](#tunnel-provider)
8. [VPN Provider](#vpn-provider)
9. [RDP Provider](#rdp-provider)
10. [Policy Engine](#policy-engine)
11. [Audit Logging](#audit-logging)
12. [Error Handling](#error-handling)
13. [Examples](#examples)

## Overview

OpenAccess MCP is a secure, policy-driven server that provides remote access capabilities through various protocols. It implements the Model Context Protocol (MCP) and offers tools for SSH execution, file transfer, synchronization, tunneling, VPN management, and remote desktop access.

### Base URL

```
mcp://localhost:8000
```

### Protocol Version

- **MCP Version**: 1.13.1
- **OpenAccess Version**: 0.0.1

## Authentication

### Authentication Methods

1. **JWT Token**: Bearer token in Authorization header
2. **Caller Identity**: Username passed in tool calls
3. **File-based**: Local user database with password/key authentication

### Authentication Context

```json
{
  "username": "admin",
  "roles": ["admin", "operator"],
  "permissions": ["ssh:execute", "sftp:transfer", "tunnel:create"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### Required Headers

```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

## Core Concepts

### Profiles

A profile defines a remote host configuration with authentication and policy settings.

```json
{
  "id": "production-server",
  "host": "192.168.1.100",
  "port": 22,
  "protocols": ["ssh", "sftp", "rsync", "tunnel"],
  "auth": {
    "type": "vault_ref",
    "ref": "prod-server-creds"
  },
  "policy": {
    "roles": ["admin", "devops"],
    "command_allowlist": ["^ls$", "^pwd$", "^git pull$"],
    "command_denylist": ["^rm -rf", "^sudo"],
    "deny_sudo": true,
    "max_session_seconds": 1800,
    "record_session": true,
    "require_change_ticket_for": ["delete", "sudo", "deploy"],
    "max_concurrent_sessions": 2
  },
  "tags": ["production", "web-server"],
  "description": "Production web server"
}
```

### Policies

Policies define access control rules for profiles.

```json
{
  "roles": ["admin", "operator"],
  "command_allowlist": ["^[a-zA-Z0-9_]+$"],
  "command_denylist": ["^rm", "^sudo", "^su"],
  "deny_sudo": true,
  "max_session_seconds": 3600,
  "record_session": true,
  "require_change_ticket_for": ["delete", "sudo", "restart"],
  "max_concurrent_sessions": 3
}
```

## SSH Provider

### Tool: `ssh.exec`

Execute commands on remote hosts via SSH.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `command` | string | Yes | Command to execute |
| `timeout` | integer | No | Command timeout in seconds (default: 300) |
| `change_ticket` | string | No | Change ticket for restricted operations |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "stdout": "command output",
    "stderr": "error output",
    "exit_code": 0,
    "session_id": "session-123",
    "execution_time": 1.23
  },
  "error": null,
  "metadata": {
    "profile_id": "production-server",
    "command": "ls -la",
    "actor": "admin"
  }
}
```

#### Example

```bash
# Execute a simple command
curl -X POST "mcp://localhost:8000/tools/ssh.exec" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "command": "ls -la /var/www",
    "caller": "admin"
  }'
```

## SFTP Provider

### Tool: `sftp.transfer`

Transfer files between local and remote systems via SFTP.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `direction` | string | Yes | Transfer direction: "upload" or "download" |
| `local_path` | string | Yes | Local file path |
| `remote_path` | string | Yes | Remote file path |
| `checksum` | boolean | No | Verify file integrity (default: true) |
| `create_dirs` | boolean | No | Create missing directories (default: true) |
| `mode` | string | No | File permissions (default: "0644") |
| `change_ticket` | string | No | Change ticket for restricted operations |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "direction": "upload",
    "remote_path": "/var/www/index.html",
    "local_path": "/tmp/index.html",
    "bytes_transferred": 1024,
    "checksum": "sha256:abc123...",
    "status": "completed"
  },
  "error": null,
  "metadata": {
    "profile_id": "production-server",
    "actor": "admin"
  }
}
```

#### Example

```bash
# Upload a file
curl -X POST "mcp://localhost:8000/tools/sftp.transfer" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "direction": "upload",
    "local_path": "/tmp/config.json",
    "remote_path": "/etc/app/config.json",
    "create_dirs": true,
    "caller": "admin"
  }'
```

## Rsync Provider

### Tool: `rsync.sync`

Synchronize files and directories between local and remote systems.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `direction` | string | Yes | Sync direction: "push" or "pull" |
| `local_path` | string | Yes | Local directory path |
| `remote_path` | string | Yes | Remote directory path |
| `delete_extras` | boolean | No | Delete extra files (default: false) |
| `preserve_permissions` | boolean | No | Preserve file permissions (default: true) |
| `preserve_timestamps` | boolean | No | Preserve timestamps (default: true) |
| `exclude` | array | No | Patterns to exclude |
| `include` | array | No | Patterns to include |
| `dry_run` | boolean | No | Show what would be done (default: false) |
| `change_ticket` | string | No | Change ticket for delete operations |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "direction": "push",
    "local_path": "/var/www",
    "remote_path": "/var/www",
    "files_transferred": 25,
    "bytes_transferred": 1024000,
    "deleted_files": 3,
    "dry_run": false,
    "status": "completed"
  },
  "error": null,
  "metadata": {
    "profile_id": "production-server",
    "actor": "admin"
  }
}
```

#### Example

```bash
# Sync a directory
curl -X POST "mcp://localhost:8000/tools/rsync.sync" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "direction": "push",
    "local_path": "/var/www",
    "remote_path": "/var/www",
    "delete_extras": true,
    "exclude": ["*.tmp", "*.log"],
    "change_ticket": "CHG-12345",
    "caller": "admin"
  }'
```

## Tunnel Provider

### Tool: `tunnel.create`

Create SSH tunnels for secure access to internal services.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `tunnel_type` | string | Yes | Tunnel type: "local", "remote", or "dynamic" |
| `target_host` | string | Yes | Target host for tunnel |
| `target_port` | integer | Yes | Target port for tunnel |
| `local_port` | integer | No | Local port for local tunnels |
| `remote_port` | integer | No | Remote port for remote tunnels |
| `change_ticket` | string | No | Change ticket for tunnel creation |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "tunnel_id": "tunnel-123",
    "tunnel_type": "local",
    "listen_port": 8080,
    "target_host": "internal.service",
    "target_port": 80,
    "profile_id": "production-server",
    "status": "active"
  },
  "error": null,
  "metadata": {
    "actor": "admin"
  }
}
```

#### Example

```bash
# Create a local tunnel
curl -X POST "mcp://localhost:8000/tools/tunnel.create" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "tunnel_type": "local",
    "target_host": "internal.web",
    "target_port": 80,
    "local_port": 8080,
    "caller": "admin"
  }'
```

### Tool: `tunnel.close`

Close an active SSH tunnel.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tunnel_id` | string | Yes | Tunnel identifier to close |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "tunnel_id": "tunnel-123",
    "status": "closed"
  },
  "error": null,
  "metadata": {
    "actor": "admin"
  }
}
```

## VPN Provider

### Tool: `vpn.wireguard_toggle`

Toggle WireGuard VPN connections on/off.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `peer_id` | string | Yes | WireGuard peer identifier |
| `action` | string | Yes | Action: "up" or "down" |
| `change_ticket` | string | No | Change ticket for VPN operations |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "status": "up",
    "interface": "wg-prod-peer",
    "peer_id": "prod-peer",
    "ip_address": "10.0.0.1",
    "error": null
  },
  "error": null,
  "metadata": {
    "profile_id": "production-server",
    "actor": "admin"
  }
}
```

#### Example

```bash
# Enable WireGuard VPN
curl -X POST "mcp://localhost:8000/tools/vpn.wireguard_toggle" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "peer_id": "prod-peer",
    "action": "up",
    "caller": "admin"
  }'
```

## RDP Provider

### Tool: `rdp.launch`

Launch Remote Desktop Protocol connections.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `profile_id` | string | Yes | Profile identifier |
| `username` | string | Yes | RDP username |
| `domain` | string | No | Windows domain |
| `resolution` | string | No | Screen resolution (default: "1920x1080") |
| `fullscreen` | boolean | No | Fullscreen mode (default: false) |
| `change_ticket` | string | No | Change ticket for RDP operations |
| `caller` | string | No | Username of the caller |

#### Response

```json
{
  "success": true,
  "data": {
    "connection_id": "rdp-123",
    "host": "192.168.1.100",
    "port": 3389,
    "username": "admin",
    "rdp_file": "full address:s:192.168.1.100:3389\nusername:s:admin",
    "connection_url": "rdp://192.168.1.100:3389",
    "status": "ready"
  },
  "error": null,
  "metadata": {
    "profile_id": "production-server",
    "actor": "admin"
  }
}
```

#### Example

```bash
# Launch RDP connection
curl -X POST "mcp://localhost:8000/tools/rdp.launch" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile_id": "production-server",
    "username": "admin",
    "resolution": "1920x1080",
    "fullscreen": false,
    "caller": "admin"
  }'
```

## Policy Engine

### Policy Enforcement

All tool calls are subject to policy enforcement based on:
- User roles and permissions
- Command allowlists/denylists
- Session limits and timeouts
- Change ticket requirements

### Policy Decision

```json
{
  "allowed": true,
  "reason": "Command allowed for admin role",
  "restrictions": [],
  "audit_required": true
}
```

### Policy Violation

```json
{
  "allowed": false,
  "reason": "Command not allowed: rm -rf /",
  "restrictions": ["dangerous_command"],
  "audit_required": true
}
```

## Audit Logging

### Audit Record Structure

```json
{
  "ts": "2024-01-15T10:30:00Z",
  "actor": "admin",
  "tool": "ssh.exec",
  "profile_id": "production-server",
  "input_hash": "sha256:abc123...",
  "stdout_hash": "sha256:def456...",
  "stderr_hash": "sha256:ghi789...",
  "result": "success",
  "ticket": "CHG-12345",
  "chain_prev": "sha256:prev123...",
  "chain_sig": "ed25519:sig123...",
  "metadata": {
    "command": "ls -la",
    "exit_code": 0
  }
}
```

### Audit Chain

Each audit record is cryptographically linked to the previous record, creating an immutable audit trail.

## Error Handling

### Error Response Format

```json
{
  "success": false,
  "data": null,
  "error": "Profile not found: non-existent",
  "metadata": {
    "error_code": "PROFILE_NOT_FOUND",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Common Error Codes

| Error Code | Description | HTTP Status |
|------------|-------------|-------------|
| `PROFILE_NOT_FOUND` | Profile does not exist | 404 |
| `POLICY_VIOLATION` | Operation violates policy | 403 |
| `AUTHENTICATION_FAILED` | Authentication failed | 401 |
| `AUTHORIZATION_FAILED` | Insufficient permissions | 403 |
| `INVALID_PARAMETERS` | Invalid input parameters | 400 |
| `INTERNAL_ERROR` | Server internal error | 500 |

### Error Handling Best Practices

1. **Always check the `success` field** in responses
2. **Handle specific error codes** for different scenarios
3. **Log error details** for debugging
4. **Implement retry logic** for transient failures
5. **Provide user-friendly error messages**

## Examples

### Complete Workflow Example

```python
import asyncio
from openaccess_mcp import OpenAccessMCPServer

async def deploy_application():
    # 1. Execute pre-deployment checks
    ssh_result = await server.ssh_exec(
        profile_id="production-server",
        command="systemctl status nginx",
        caller="admin"
    )
    
    if not ssh_result["success"]:
        raise Exception(f"Pre-deployment check failed: {ssh_result['error']}")
    
    # 2. Upload new configuration
    sftp_result = await server.sftp_transfer(
        profile_id="production-server",
        direction="upload",
        local_path="/tmp/nginx.conf",
        remote_path="/etc/nginx/nginx.conf",
        caller="admin"
    )
    
    if not sftp_result["success"]:
        raise Exception(f"Configuration upload failed: {sftp_result['error']}")
    
    # 3. Restart service
    restart_result = await server.ssh_exec(
        profile_id="production-server",
        command="systemctl reload nginx",
        change_ticket="CHG-12345",
        caller="admin"
    )
    
    if not restart_result["success"]:
        raise Exception(f"Service restart failed: {restart_result['error']}")
    
    print("Application deployed successfully!")

# Run the workflow
asyncio.run(deploy_application())
```

### Error Handling Example

```python
async def safe_ssh_exec(profile_id, command, caller):
    try:
        result = await server.ssh_exec(
            profile_id=profile_id,
            command=command,
            caller=caller
        )
        
        if not result["success"]:
            if "POLICY_VIOLATION" in result.get("metadata", {}).get("error_code", ""):
                print(f"Policy violation: {result['error']}")
                return None
            elif "PROFILE_NOT_FOUND" in result.get("metadata", {}).get("error_code", ""):
                print(f"Profile not found: {profile_id}")
                return None
            else:
                print(f"SSH execution failed: {result['error']}")
                return None
        
        return result["data"]
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
```

### Monitoring and Metrics

```python
async def get_server_metrics():
    # Get server health status
    health_result = await server.get_health()
    
    # Get active connections
    connections_result = await server.get_connections()
    
    # Get audit log statistics
    audit_stats = await server.get_audit_stats()
    
    return {
        "health": health_result,
        "connections": connections_result,
        "audit_stats": audit_stats
    }
```

## Next Steps

1. **Review the deployment guide** for production setup
2. **Configure profiles and policies** for your environment
3. **Set up monitoring and alerting** for production use
4. **Implement proper authentication** and access controls
5. **Test all functionality** in a staging environment
6. **Document your specific use cases** and workflows

For additional support and examples, refer to the [README.md](README.md) and [DEPLOYMENT.md](DEPLOYMENT.md) files.

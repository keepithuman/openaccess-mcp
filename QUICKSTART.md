# OpenAccess MCP - Quick Start Guide

This guide will get you up and running with OpenAccess MCP in minutes.

## Prerequisites

- Python 3.12+
- Docker and Docker Compose (for demo environment)
- Git

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/openaccess-mcp/openaccess-mcp.git
   cd openaccess-mcp
   ```

2. **Install dependencies:**
   ```bash
   # Install with development dependencies
   make install-dev
   
   # Or manually:
   pip install -e ".[dev]"
   ```

3. **Generate audit keys:**
   ```bash
   make generate-keys
   # This creates ./keys/audit_private.key and ./keys/audit_public.key
   ```

## Quick Start

### Option 1: Local Development

1. **Start the server:**
   ```bash
   openaccess-mcp start --profiles ./examples/profiles --secrets-dir ./examples/secrets
   ```

2. **In another terminal, test the CLI:**
   ```bash
   # List profiles
   openaccess-mcp profiles
   
   # Show audit stats
   openaccess-mcp audit
   
   # Verify audit log integrity
   openaccess-mcp verify
   ```

### Option 2: Docker Demo

1. **Start demo environment:**
   ```bash
   make docker-compose-up
   ```

2. **Test the setup:**
   ```bash
   # The server is now running on port 8080
   # SSH target is available on port 2222
   
   # Test SSH connection to demo target
   ssh -p 2222 testuser@localhost
   # Password: testpass
   ```

## Example Usage

### SSH Execution

```python
# Execute a command on a remote host
result = await mcp.call_tool("ssh.exec", {
    "profile_id": "prod-web-01",
    "command": "systemctl status nginx",
    "timeout_seconds": 30
})
```

### File Transfer

```python
# Download a file securely
result = await mcp.call_tool("sftp.transfer", {
    "profile_id": "prod-web-01",
    "direction": "get",
    "remote_path": "/var/log/nginx/access.log",
    "local_path": "./nginx-access.log"
})
```

### Synchronization with Safety

```python
# First, dry-run to see what would change
plan = await mcp.call_tool("rsync.sync", {
    "profile_id": "prod-web-01",
    "direction": "push",
    "source": "./dist/",
    "dest": "/var/www/html/",
    "delete_extras": True,
    "dry_run": True
})

# Then apply if the plan looks correct
result = await mcp.call_tool("rsync.sync", {
    "profile_id": "prod-web-01",
    "direction": "push",
    "source": "./dist/",
    "dest": "/var/www/html/",
    "delete_extras": True,
    "dry_run": False,
    "change_ticket": "CHG-12345"
})
```

## Configuration

### Profiles

Profiles define remote hosts and their access policies. See `examples/profiles/` for examples.

### Secrets

Secrets are stored securely and referenced by profiles. Supported backends:
- **File-based** (development): `examples/secrets/`
- **HashiCorp Vault** (production): Set `--vault-addr` and `--vault-token`
- **OS Keychain** (optional): Automatically enabled if available

### Policies

Each profile has a policy that defines:
- **Roles**: Who can access this profile
- **Command allowlist**: What commands are allowed
- **Command denylist**: What commands are forbidden
- **Sudo restrictions**: Whether sudo is allowed
- **Session limits**: Timeout and concurrent session limits
- **Change tickets**: Operations requiring approval

## Development

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/test_types.py -v
```

### Code Quality

```bash
# Lint code
make lint

# Format code
make format

# Clean build artifacts
make clean
```

### Docker Development

```bash
# Build image
make docker-build

# Run container
make docker-run

# Start demo services
make docker-compose-up
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure you've installed with `pip install -e .`
2. **Permission errors**: Check file permissions on secrets and profiles
3. **SSH connection failures**: Verify host connectivity and credentials
4. **Policy violations**: Check profile policies and your assigned roles

### Debug Mode

Enable verbose logging:
```bash
openaccess-mcp start --profiles ./examples/profiles --verbose
```

### Audit Logs

Check audit logs for detailed operation history:
```bash
# View audit statistics
openaccess-mcp audit

# Verify log integrity
openaccess-mcp verify

# Extract specific records
openaccess-audit extract-records audit.log --tool ssh.exec
```

## Next Steps

- Read the [full documentation](docs/)
- Explore the [security model](docs/security.md)
- Check out the [policy cookbook](docs/policy-cookbook.md)
- Join our [community discussions](https://github.com/openaccess-mcp/openaccess-mcp/discussions)

## Support

- **Issues**: [GitHub Issues](https://github.com/openaccess-mcp/openaccess-mcp/issues)
- **Security**: [security@openaccess-mcp.dev](mailto:security@openaccess-mcp.dev)
- **Discussions**: [GitHub Discussions](https://github.com/openaccess-mcp/openaccess-mcp/discussions)

---

**Happy coding! 🚀**

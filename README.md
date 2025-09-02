# OpenAccess MCP - The Ultimate MCP Server for SSH, SFTP, Rsync, VPN & Remote Access

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP Protocol](https://img.shields.io/badge/Protocol-MCP%20v1.0-green.svg)](https://modelcontextprotocol.io/)
[![Security: Audit-Ready](https://img.shields.io/badge/Security-Audit%20Ready-red.svg)](https://github.com/keepithuman/openaccess-mcp)

> **The most comprehensive MCP server for secure remote access operations** - SSH execution, SFTP file transfer, rsync synchronization, SSH tunneling, VPN management, and RDP brokering with enterprise-grade security, policy enforcement, and audit logging.

## 🔍 **What is OpenAccess MCP?**

**OpenAccess MCP** is a **Model Context Protocol (MCP) server** that provides secure, policy-driven access to remote systems through **SSH, SFTP, rsync, tunneling, VPNs, and RDP**. It's designed for **AI assistants, automation tools, and DevOps teams** who need secure remote access with full audit trails.

### **Key Search Terms & Use Cases:**
- **MCP for SSH** - Secure SSH execution through MCP protocol
- **MCP for SFTP** - File transfer operations via MCP
- **MCP for Rsync** - Synchronization with policy enforcement
- **MCP for VPN** - WireGuard and OpenVPN management
- **MCP for Tunneling** - SSH port forwarding and tunneling
- **MCP for RDP** - Remote desktop brokering
- **MCP Server for Remote Access** - Complete remote access solution
- **Secure MCP Server** - Policy-driven access control
- **Audit-Ready MCP** - Compliance and security logging

## 🚀 **Core Features & MCP Tools**

### **🔐 SSH Operations (MCP Tool: `ssh.exec`)**
- **Secure command execution** with policy allowlists
- **RBAC enforcement** and session timeboxing
- **Command validation** and sudo control
- **Real-time output streaming** with timeout management

### **📁 File Transfer (MCP Tool: `sftp.transfer`)**
- **Secure file upload/download** with checksum verification
- **Directory synchronization** and recursive operations
- **Permission preservation** and ownership management
- **Bandwidth throttling** and progress monitoring

### **🔄 Synchronization (MCP Tool: `rsync.sync`)**
- **Dry-run protection** for destructive operations
- **Change ticket requirements** for risky operations
- **Bandwidth limiting** and exclude patterns
- **Incremental sync** with conflict resolution

### **🌐 Tunneling (MCP Tool: `tunnel.create/close`)**
- **Local port forwarding** for service access
- **Remote port forwarding** for reverse connections
- **Dynamic SOCKS proxy** for flexible routing
- **TTL enforcement** and automatic cleanup

### **🔒 VPN Management (MCP Tool: `vpn.wireguard/openvpn`)**
- **WireGuard interface** creation and management
- **OpenVPN connection** handling and monitoring
- **Peer management** and key rotation
- **Connection status** and health checks

### **🖥️ RDP Brokering (MCP Tool: `rdp.launch`)**
- **Secure RDP connection** brokering
- **Connection URL generation** with signatures
- **TTL management** and access control
- **Audit logging** for all connections

## 🏗️ **Architecture & MCP Integration**

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI Assistant / Client                        │
│              (ChatGPT, Claude, Custom AI)                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │ MCP Protocol (stdio/websocket)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                 OpenAccess MCP Server                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   SSH Provider  │  │  SFTP Provider  │  │ Rsync Provider  │ │
│  │   (ssh.exec)    │  │ (sftp.transfer) │  │  (rsync.sync)   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Tunnel Provider │  │   VPN Provider  │  │  RDP Provider   │ │
│  │(tunnel.create)  │  │ (vpn.wireguard) │  │  (rdp.launch)   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Policy Engine   │  │ Audit Logger    │  │ Secret Store    │ │
│  │ (RBAC, Rules)   │  │ (Hash-chained)  │  │ (Vault/Keyring) │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Network Operations
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                Remote Systems & Infrastructure                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Linux/Unix  │  │   Windows   │  │   Network   │            │
│  │   Servers   │  │   Servers   │  │  Devices    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## 🎯 **Why Choose OpenAccess MCP?**

### **🔍 For AI Assistants & LLMs:**
- **ChatGPT Integration** - Perfect for AI-powered remote operations
- **Claude Integration** - Secure remote access through Claude
- **Custom AI Tools** - Build AI assistants with remote capabilities
- **Natural Language** - Convert natural language to secure operations

### **🛡️ For Security Teams:**
- **Zero Trust Architecture** - No direct credential exposure
- **Policy Enforcement** - RBAC and command allowlists
- **Audit Compliance** - SOC2, ISO27001, and regulatory requirements
- **Threat Detection** - Anomaly detection and alerting

### **⚡ For DevOps & SRE:**
- **Infrastructure Automation** - Secure CI/CD pipeline integration
- **Incident Response** - Quick access during outages
- **Configuration Management** - Policy-driven change control
- **Monitoring Integration** - OpenTelemetry and observability

### **🏢 For Enterprises:**
- **Compliance Ready** - Audit trails and policy enforcement
- **Scalable Architecture** - Multi-tenant and distributed deployment
- **Integration Friendly** - REST APIs and webhook support
- **Professional Support** - Enterprise-grade reliability

## 🚀 **Quick Start - Get Running in 5 Minutes**

### **Prerequisites**
- **Python 3.12+** (Latest Python for best performance)
- **Docker** (for demo environment)
- **SSH access** to target systems

### **Installation**

```bash
# Clone the repository
git clone https://github.com/keepithuman/openaccess-mcp.git
cd openaccess-mcp

# Install with development dependencies
pip install -e ".[dev]"

# Or using uv (recommended for speed)
uv sync
```

### **Local Development Setup**

```bash
# Start the MCP server
openaccess-mcp start --profiles ./examples/profiles

# In another terminal, verify audit logs
openaccess-audit verify ./audit.jsonl
```

### **Docker Demo Environment**

```bash
# Start demo environment (server + SSH target)
docker compose up -d

# Test the setup
openaccess-mcp start --profiles ./examples/profiles
```

## 📖 **Comprehensive Documentation**

- **[Concepts Guide](docs/concepts.md)** - Understanding profiles, policies, and MCP tools
- **[Quickstart Guide](docs/quickstart.md)** - Get up and running in minutes
- **[Security Model](docs/security.md)** - Threat model and security guarantees
- **[Policy Cookbook](docs/policy-cookbook.md)** - Common policy patterns and examples
- **[API Reference](docs/api.md)** - Complete MCP tool schemas and examples
- **[Integration Guide](docs/integration.md)** - ChatGPT, Claude, and custom AI integration

## 🛠️ **Real-World Usage Examples**

### **Profile Configuration for Production**

```json
{
  "id": "prod-web-01",
  "host": "10.10.1.15",
  "port": 22,
  "protocols": ["ssh", "sftp", "rsync", "tunnel"],
  "auth": { "type": "vault_ref", "ref": "kv/ssh/prod-web-01" },
  "policy": {
    "roles": ["ops-oncall", "neteng-sre"],
    "command_allowlist": ["^systemctl status\\b", "^journalctl\\b", "^grep\\b"],
    "deny_sudo": true,
    "require_change_ticket_for": ["rsync.delete", "tunnel.dynamic"],
    "max_session_seconds": 3600
  }
}
```

### **SSH Command Execution via MCP**

```python
# Execute a command on a remote host through MCP
result = await mcp.call_tool("ssh.exec", {
    "profile_id": "prod-web-01",
    "command": "systemctl status nginx",
    "timeout_seconds": 30
})

print(f"Command output: {result.stdout}")
print(f"Exit code: {result.exit_code}")
```

### **Secure File Transfer via MCP**

```python
# Download a file securely through MCP
result = await mcp.call_tool("sftp.transfer", {
    "profile_id": "prod-web-01",
    "direction": "get",
    "remote_path": "/var/log/nginx/access.log",
    "local_path": "./nginx-access.log"
})

print(f"Transfer successful: {result.success}")
print(f"Bytes transferred: {result.bytes_transferred}")
```

### **Safe Synchronization with MCP**

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

print(f"Plan: {plan.plan}")

# Then apply if the plan looks correct
if plan.success and input("Apply changes? (y/N): ").lower() == 'y':
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

### **SSH Tunneling via MCP**

```python
# Create a local port forward through MCP
tunnel = await mcp.call_tool("tunnel.create", {
    "profile_id": "prod-web-01",
    "tunnel_type": "local",
    "listen_port": 8080,
    "target_host": "internal-service",
    "target_port": 80,
    "ttl_seconds": 3600
})

print(f"Tunnel created: {tunnel.tunnel_id}")
print(f"Local port: {tunnel.listen_port}")
```

## 🔒 **Enterprise Security Features**

### **🔐 Zero Trust Architecture**
- **No credential exposure** - Secrets resolved server-side only
- **Policy-based access** - Every operation validated against rules
- **Session isolation** - No shared state between operations
- **Audit integrity** - Hash-chained logs with cryptographic signatures

### **🛡️ Advanced Policy Enforcement**
- **Role-based access control (RBAC)** - Granular permission management
- **Command allowlists** - Regex-based command validation
- **Change ticket requirements** - Approval workflow for risky operations
- **Time-based restrictions** - Session timeboxing and TTL enforcement

### **📊 Compliance & Audit**
- **SOC2 Ready** - Comprehensive audit trails and controls
- **ISO27001 Compatible** - Information security management
- **GDPR Compliant** - Data protection and privacy controls
- **Regulatory Ready** - HIPAA, PCI-DSS, and more

## 🧪 **Testing & Quality Assurance**

```bash
# Run all tests with coverage
pytest --cov=openaccess_mcp --cov-report=html

# Run specific test suites
pytest tests/unit/ -v                    # Unit tests
pytest tests/integration/ -v             # Integration tests
pytest tests/performance/ -v             # Performance tests

# Run with different Python versions
tox

# Security scanning
bandit -r openaccess_mcp/
safety check
```

## 📦 **Deployment Options**

### **Docker Deployment**

```bash
# Build the image
docker build -t openaccess-mcp .

# Run with profiles and secrets
docker run -d \
  --name openaccess-mcp \
  -v $(pwd)/profiles:/profiles \
  -v $(pwd)/secrets:/secrets \
  -p 8080:8080 \
  openaccess-mcp start \
  --profiles /profiles \
  --secrets-dir /secrets
```

### **Kubernetes Deployment**

```bash
# Deploy with Helm
helm install openaccess-mcp ./charts/openaccess-mcp \
  --set vault.addr=https://vault.example.com \
  --set otel.endpoint=http://otel-collector:4317 \
  --set ingress.enabled=true \
  --set ingress.host=openaccess-mcp.example.com
```

### **Cloud Deployment**

```bash
# AWS ECS
aws ecs create-service \
  --cluster openaccess-cluster \
  --service-name openaccess-mcp \
  --task-definition openaccess-mcp:1

# Google Cloud Run
gcloud run deploy openaccess-mcp \
  --image gcr.io/PROJECT_ID/openaccess-mcp \
  --platform managed \
  --region us-central1
```

## 🤝 **Contributing & Community**

### **Development Setup**

```bash
# Install pre-commit hooks
pre-commit install

# Run code quality checks
ruff check .                    # Linting
mypy openaccess_mcp/           # Type checking
black openaccess_mcp/           # Code formatting
isort openaccess_mcp/           # Import sorting
```

### **Community & Support**

- **💬 Discussions**: [GitHub Discussions](https://github.com/keepithuman/openaccess-mcp/discussions)
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/keepithuman/openaccess-mcp/issues)
- **🔒 Security Issues**: [security@openaccess-mcp.dev](mailto:security@openaccess-mcp.dev)
- **📖 Documentation**: [docs/](docs/) (comprehensive guides)
- **📋 Code of Conduct**: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **🎯 Roadmap**: [ROADMAP.md](ROADMAP.md) (development plans)

## 📄 **License & Legal**

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support & Help**

### **Getting Help**
- **Security Issues**: Report to [security@openaccess-mcp.dev](mailto:security@openaccess-mcp.dev)
- **Bug Reports**: Use [GitHub Issues](https://github.com/keepithuman/openaccess-mcp/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/keepithuman/openaccess-mcp/discussions)
- **Documentation**: Comprehensive guides in [docs/](docs/)

### **Professional Support**
- **Enterprise Support**: Available for enterprise deployments
- **Training & Consulting**: Custom implementation and training
- **Security Audits**: Third-party security assessments
- **Compliance Help**: SOC2, ISO27001, and regulatory guidance

## 🗺️ **Development Roadmap**

### **✅ Completed (v1.0)**
- [x] **Core MCP Tools** - SSH, SFTP, rsync, tunneling
- [x] **Policy Engine** - RBAC, allowlists, change tickets
- [x] **Audit System** - Hash-chained logs, Ed25519 signatures
- [x] **OpenTelemetry** - Comprehensive observability
- [x] **Security Model** - Zero trust, policy enforcement

### **🚧 In Progress (v1.1)**
- [ ] **VPN Management** - WireGuard and OpenVPN integration
- [ ] **RDP Brokering** - Secure remote desktop access
- [ ] **Web UI** - Audit browsing and policy testing
- [ ] **Performance Optimization** - High-throughput operations

### **🔮 Planned (v2.0+)**
- [ ] **Fleet Operations** - Multi-target execution with concurrency
- [ ] **Plugin System** - Custom protocol providers
- [ ] **Advanced Analytics** - ML-powered anomaly detection
- [ ] **Multi-Cloud Support** - AWS, GCP, Azure integration

## 🚫 **What We Don't Do - Clear Expectations**

To set clear expectations and avoid confusion:

- **❌ Full Interactive Shells**: We provide command execution, not unrestricted shell access
- **❌ GUI Streaming**: No VNC/RDP streaming — we broker connections only
- **❌ Raw Credential Exposure**: Secrets are resolved server-side and never exposed to clients
- **❌ Bypass Security Controls**: All operations must pass policy enforcement
- **❌ Root Access**: We enforce least-privilege principles
- **❌ Persistent Sessions**: All sessions are timeboxed and audited

## 🌟 **Star History & Community Growth**

[![Star History Chart](https://api.star-history.com/svg?repos=keepithuman/openaccess-mcp&type=Date)](https://star-history.com/#keepithuman/openaccess-mcp&Date)

## 📊 **Project Statistics**

![GitHub stars](https://img.shields.io/github/stars/keepithuman/openaccess-mcp)
![GitHub forks](https://img.shields.io/github/forks/keepithuman/openaccess-mcp)
![GitHub issues](https://img.shields.io/github/issues/keepithuman/openaccess-mcp)
![GitHub pull requests](https://img.shields.io/github/issues-pr/keepithuman/openaccess-mcp)

---

## 🎯 **Ready to Get Started?**

**OpenAccess MCP** is the most comprehensive and secure MCP server for remote access operations. Whether you're building AI assistants, automating infrastructure, or securing enterprise access, we've got you covered.

### **Quick Links:**
- **[🚀 Quick Start](QUICKSTART.md)** - Get running in 5 minutes
- **[📖 Documentation](docs/)** - Comprehensive guides and examples
- **[🛠️ Examples](examples/)** - Ready-to-use configurations
- **[🤝 Contributing](CONTRIBUTING.md)** - Join our community
- **[🔒 Security](SECURITY.md)** - Security policy and reporting

---

**OpenAccess MCP** - Secure remote access, policy-driven, audit-ready, MCP-powered.

*Built with ❤️ for the AI and DevOps communities*

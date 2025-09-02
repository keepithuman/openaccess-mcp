"""Core data models for OpenAccess MCP."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, validator
import hashlib
import json


class AuthRef(BaseModel):
    """Reference to authentication credentials stored securely."""
    
    type: Literal["vault_ref", "file_ref", "keychain_ref"]
    ref: str
    
    @validator("ref")
    def validate_ref(cls, v: str) -> str:
        """Validate reference format based on type."""
        if not v or not v.strip():
            raise ValueError("Reference cannot be empty")
        return v.strip()


class Policy(BaseModel):
    """Access control policy for a profile."""
    
    roles: List[str] = Field(default_factory=list, description="Allowed roles for this profile")
    command_allowlist: List[str] = Field(
        default_factory=list, 
        description="Regex patterns for allowed commands"
    )
    command_denylist: List[str] = Field(
        default_factory=list,
        description="Regex patterns for denied commands"
    )
    deny_sudo: bool = Field(default=True, description="Whether sudo is denied by default")
    max_session_seconds: int = Field(default=900, description="Maximum session duration in seconds")
    record_session: bool = Field(default=True, description="Whether to record session output")
    require_change_ticket_for: List[str] = Field(
        default_factory=list,
        description="Operations that require a change ticket"
    )
    max_concurrent_sessions: int = Field(default=1, description="Maximum concurrent sessions per user")
    
    @validator("max_session_seconds")
    def validate_session_timeout(cls, v: int) -> int:
        """Validate session timeout is reasonable."""
        if v < 60 or v > 86400:  # 1 minute to 24 hours
            raise ValueError("Session timeout must be between 60 and 86400 seconds")
        return v
    
    @validator("max_concurrent_sessions")
    def validate_concurrent_sessions(cls, v: int) -> int:
        """Validate concurrent sessions limit."""
        if v < 1 or v > 10:
            raise ValueError("Concurrent sessions must be between 1 and 10")
        return v


class Profile(BaseModel):
    """Remote host profile configuration."""
    
    id: str = Field(..., description="Unique profile identifier")
    host: str = Field(..., description="Remote host address")
    port: int = Field(default=22, description="SSH port")
    protocols: List[str] = Field(
        default_factory=lambda: ["ssh", "sftp", "rsync", "tunnel"],
        description="Enabled protocols for this profile"
    )
    auth: AuthRef = Field(..., description="Authentication reference")
    policy: Policy = Field(..., description="Access control policy")
    tags: List[str] = Field(default_factory=list, description="Profile tags for organization")
    description: Optional[str] = Field(None, description="Human-readable description")
    
    @validator("id")
    def validate_id(cls, v: str) -> str:
        """Validate profile ID format."""
        if not v or not v.strip():
            raise ValueError("Profile ID cannot be empty")
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Profile ID must be alphanumeric with hyphens/underscores only")
        return v.strip()
    
    @validator("host")
    def validate_host(cls, v: str) -> str:
        """Validate host address."""
        if not v or not v.strip():
            raise ValueError("Host cannot be empty")
        return v.strip()
    
    @validator("port")
    def validate_port(cls, v: int) -> int:
        """Validate port number."""
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @validator("protocols")
    def validate_protocols(cls, v: List[str]) -> List[str]:
        """Validate protocol list."""
        valid_protocols = {"ssh", "sftp", "rsync", "tunnel", "vpn", "rdp"}
        for protocol in v:
            if protocol not in valid_protocols:
                raise ValueError(f"Invalid protocol: {protocol}. Valid: {valid_protocols}")
        return list(set(v))  # Remove duplicates


class Capabilities(BaseModel):
    """Server capabilities and enabled features."""
    
    protocols: Dict[str, Dict[str, bool]] = Field(
        default_factory=lambda: {
            "ssh": {"exec": True, "pty": True, "tunnel": True},
            "sftp": {"put": True, "get": True, "checksum": True},
            "rsync": {"push": True, "pull": True, "dry_run": True},
            "tunnel": {"local": True, "remote": True, "dynamic": False},
            "vpn": {"wireguard": False, "openvpn": False},
            "rdp": {"broker": False},
        },
        description="Protocol capabilities and features"
    )
    features: Dict[str, bool] = Field(
        default_factory=lambda: {
            "audit_signing": True,
            "policy_enforcement": True,
            "secret_management": True,
            "otel_export": True,
            "session_recording": True,
        },
        description="Feature flags"
    )
    limits: Dict[str, int] = Field(
        default_factory=lambda: {
            "max_profiles": 1000,
            "max_concurrent_tools": 50,
            "max_audit_log_size_mb": 1024,
            "max_session_output_mb": 100,
        },
        description="System limits"
    )


class AuditRecord(BaseModel):
    """Tamper-evident audit log record."""
    
    ts: str = Field(..., description="ISO timestamp")
    actor: str = Field(..., description="Actor identifier (user/agent)")
    tool: str = Field(..., description="Tool name that was called")
    profile_id: str = Field(..., description="Target profile ID")
    input_hash: str = Field(..., description="SHA256 hash of input parameters")
    stdout_hash: Optional[str] = Field(None, description="SHA256 hash of stdout")
    stderr_hash: Optional[str] = Field(None, description="SHA256 hash of stderr")
    result: Literal["success", "failure", "dry_run", "policy_denied"] = Field(..., description="Operation result")
    ticket: Optional[str] = Field(None, description="Change ticket if required")
    chain_prev: Optional[str] = Field(None, description="Previous record hash for chaining")
    chain_sig: Optional[str] = Field(None, description="Ed25519 signature of this record")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator("ts")
    def validate_timestamp(cls, v: str) -> str:
        """Validate ISO timestamp format."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError("Invalid ISO timestamp format")
    
    @validator("input_hash")
    def validate_input_hash(cls, v: str) -> str:
        """Validate hash format."""
        if not v.startswith("sha256:"):
            raise ValueError("Input hash must start with 'sha256:'")
        if len(v) != 71:  # sha256: + 64 hex chars
            raise ValueError("Invalid SHA256 hash length")
        return v
    
    @validator("stdout_hash", "stderr_hash")
    def validate_output_hash(cls, v: Optional[str]) -> Optional[str]:
        """Validate output hash format if present."""
        if v is None:
            return v
        if not v.startswith("sha256:"):
            raise ValueError("Output hash must start with 'sha256:'")
        if len(v) != 71:
            raise ValueError("Invalid SHA256 hash length")
        return v
    
    def compute_hash(self) -> str:
        """Compute the hash of this record for chaining."""
        # Create a deterministic representation for hashing
        record_data = {
            "ts": self.ts,
            "actor": self.actor,
            "tool": self.tool,
            "profile_id": self.profile_id,
            "input_hash": self.input_hash,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "result": self.result,
            "ticket": self.ticket,
            "chain_prev": self.chain_prev,
            "metadata": dict(sorted(self.metadata.items()))
        }
        
        record_json = json.dumps(record_data, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(record_json.encode()).hexdigest()}"
    
    def to_jsonl(self) -> str:
        """Convert to JSONL format for logging."""
        return json.dumps(self.dict(), separators=(",", ":"))


class SecretData(BaseModel):
    """Resolved secret data (never logged or returned to clients)."""
    
    username: str
    private_key: Optional[str] = None
    password: Optional[str] = None
    passphrase: Optional[str] = None
    
    @validator("username")
    def validate_username(cls, v: str) -> str:
        """Validate username."""
        if not v or not v.strip():
            raise ValueError("Username cannot be empty")
        return v.strip()
    
    def has_key_auth(self) -> bool:
        """Check if this secret has key-based authentication."""
        return bool(self.private_key)
    
    def has_password_auth(self) -> bool:
        """Check if this secret has password-based authentication."""
        return bool(self.password)
    
    def get_auth_methods(self) -> List[str]:
        """Get list of available authentication methods."""
        methods = []
        if self.has_key_auth():
            methods.append("key")
        if self.has_password_auth():
            methods.append("password")
        return methods


class ToolResult(BaseModel):
    """Standard result structure for tool calls."""
    
    success: bool = Field(..., description="Whether the operation succeeded")
    data: Optional[Dict[str, Any]] = Field(None, description="Result data if successful")
    error: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @classmethod
    def success_result(cls, data: Dict[str, Any], **metadata) -> "ToolResult":
        """Create a successful result."""
        return cls(success=True, data=data, metadata=metadata)
    
    @classmethod
    def error_result(cls, error: str, **metadata) -> "ToolResult":
        """Create an error result."""
        return cls(success=False, error=error, metadata=metadata)
    
    @classmethod
    def dry_run_result(cls, plan: str, **metadata) -> "ToolResult":
        """Create a dry-run result."""
        return cls(success=True, data={"plan": plan, "dry_run": True}, metadata=metadata)


class PolicyDecision(BaseModel):
    """Result of a policy enforcement check."""
    
    allowed: bool = Field(..., description="Whether the operation is allowed")
    reason: Optional[str] = Field(None, description="Reason for decision")
    required_ticket: Optional[str] = Field(None, description="Required change ticket if any")
    restrictions: List[str] = Field(default_factory=list, description="Applied restrictions")
    
    @classmethod
    def allow(cls, **kwargs) -> "PolicyDecision":
        """Create an allow decision."""
        return cls(allowed=True, **kwargs)
    
    @classmethod
    def deny(cls, reason: str, **kwargs) -> "PolicyDecision":
        """Create a deny decision."""
        return cls(allowed=False, reason=reason, **kwargs)

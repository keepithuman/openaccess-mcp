"""Tests for core types."""

import pytest
from openaccess_mcp.types import Profile, Policy, AuthRef, Capabilities


def test_auth_ref_validation():
    """Test AuthRef validation."""
    # Valid auth ref
    auth = AuthRef(type="file_ref", ref="test-secret")
    assert auth.type == "file_ref"
    assert auth.ref == "test-secret"
    
    # Invalid empty ref
    with pytest.raises(ValueError, match="Reference cannot be empty"):
        AuthRef(type="file_ref", ref="")


def test_policy_validation():
    """Test Policy validation."""
    # Valid policy
    policy = Policy(
        roles=["admin"],
        command_allowlist=["^ls\\b"],
        max_session_seconds=1800
    )
    assert policy.roles == ["admin"]
    assert policy.max_session_seconds == 1800
    
    # Invalid session timeout
    with pytest.raises(ValueError, match="Session timeout must be between"):
        Policy(max_session_seconds=30)  # Too short
    
    with pytest.raises(ValueError, match="Session timeout must be between"):
        Policy(max_session_seconds=100000)  # Too long


def test_profile_validation():
    """Test Profile validation."""
    auth = AuthRef(type="file_ref", ref="test-secret")
    policy = Policy(roles=["admin"])
    
    # Valid profile
    profile = Profile(
        id="test-server",
        host="192.168.1.100",
        port=22,
        auth=auth,
        policy=policy
    )
    assert profile.id == "test-server"
    assert profile.host == "192.168.1.100"
    assert profile.port == 22
    
    # Invalid port
    with pytest.raises(ValueError, match="Port must be between"):
        Profile(
            id="test-server",
            host="192.168.1.100",
            port=70000,
            auth=auth,
            policy=policy
        )
    
    # Invalid protocols
    with pytest.raises(ValueError, match="Invalid protocol"):
        Profile(
            id="test-server",
            host="192.168.1.100",
            auth=auth,
            policy=policy,
            protocols=["invalid_protocol"]
        )


def test_capabilities_defaults():
    """Test Capabilities default values."""
    capabilities = Capabilities()
    
    assert capabilities.protocols["ssh"]["exec"] is True
    assert capabilities.protocols["sftp"]["put"] is True
    assert capabilities.protocols["rdp"]["broker"] is False
    
    assert capabilities.features["audit_signing"] is True
    assert capabilities.features["policy_enforcement"] is True

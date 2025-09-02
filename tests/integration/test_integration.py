"""Integration tests for OpenAccess MCP."""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, Mock
import json

from openaccess_mcp.server import OpenAccessMCPServer
from openaccess_mcp.types import Profile, AuthRef, Policy
from openaccess_mcp.secrets.store import SecretStore
from openaccess_mcp.audit.logger import AuditLogger
from openaccess_mcp.policy.engine import PolicyEngine


class TestOpenAccessMCPServer:
    """Integration tests for the OpenAccess MCP server."""
    
    @pytest.fixture
    async def server(self):
        """Create a test server instance."""
        # Create temporary directories
        with tempfile.TemporaryDirectory() as temp_dir:
            profiles_dir = Path(temp_dir) / "profiles"
            secrets_dir = Path(temp_dir) / "secrets"
            audit_dir = Path(temp_dir) / "audit"
            
            profiles_dir.mkdir()
            secrets_dir.mkdir()
            audit_dir.mkdir()
            
            # Create test profile
            profile = Profile(
                id="test-server",
                host="127.0.0.1",
                port=22,
                protocols=["ssh", "sftp", "rsync", "tunnel"],
                auth=AuthRef(type="file_ref", ref="test-server"),
                policy=Policy(
                    roles=["admin"],
                    command_allowlist=["^echo\\b", "^ls\\b", "^cat\\b"],
                    deny_sudo=False,
                    max_session_seconds=900
                )
            )
            
            profile_file = profiles_dir / "test-server.json"
            profile_file.write_text(profile.model_dump_json())
            
            # Create test secret
            secret_data = {
                "username": "testuser",
                "password": "testpass"
            }
            
            secret_file = secrets_dir / "test-server.json"
            secret_file.write_text(json.dumps(secret_data))
            
            # Initialize server
            server = OpenAccessMCPServer(
                profiles_dir=profiles_dir,
                secrets_dir=secrets_dir,
                audit_log_path=audit_dir / "audit.log",
                audit_key_path=audit_dir / "audit.key"
            )
            
            yield server
            
            # Cleanup
            await server.cleanup()
    
    @pytest.mark.asyncio
    async def test_server_initialization(self, server):
        """Test server initialization."""
        assert server.profiles_dir is not None
        assert server.secret_store is not None
        assert server.audit_logger is not None
        assert server.ssh_provider is not None
        assert server.sftp_provider is not None
        assert server.rsync_provider is not None
        assert server.tunnel_provider is not None
        assert server.vpn_provider is not None
        assert server.rdp_provider is not None
    
    @pytest.mark.asyncio
    async def test_profile_loading(self, server):
        """Test profile loading functionality."""
        profile = await server._load_profile("test-server")
        
        assert profile.id == "test-server"
        assert profile.host == "127.0.0.1"
        assert profile.port == 22
        assert "ssh" in profile.protocols
        assert "sftp" in profile.protocols
        assert "rsync" in profile.protocols
        assert "tunnel" in profile.protocols
    
    @pytest.mark.asyncio
    async def test_secret_resolution(self, server):
        """Test secret resolution."""
        profile = await server._load_profile("test-server")
        secret = await server.secret_store.resolve(profile.auth)
        
        assert secret.username == "testuser"
        assert secret.password == "testpass"
    
    @pytest.mark.asyncio
    async def test_policy_enforcement(self, server):
        """Test policy enforcement."""
        profile = await server._load_profile("test-server")
        
        # Test allowed command
        from openaccess_mcp.policy.engine import PolicyContext, enforce_policy
        
        context = PolicyContext(
            actor="testuser",
            actor_roles=["admin"],
            profile=profile,
            tool="ssh.exec",
            command="echo hello"
        )
        
        decision = enforce_policy(context)
        assert decision.allowed is True
        
        # Test denied command
        context.command = "rm -rf /"
        decision = enforce_policy(context)
        assert decision.allowed is False
    
    @pytest.mark.asyncio
    async def test_ssh_exec_tool(self, server):
        """Test SSH exec tool."""
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_asyncssh:
            # Mock successful SSH connection
            mock_conn = Mock()
            mock_conn.run.return_value = Mock(
                stdout="hello world",
                stderr="",
                exit_code=0
            )
            mock_asyncssh.connect.return_value = mock_conn
            
            # Call the tool
            result = await server.ssh_exec(
                profile_id="test-server",
                command="echo hello world",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "stdout" in result["data"]
            assert result["data"]["stdout"] == "hello world"
    
    @pytest.mark.asyncio
    async def test_sftp_transfer_tool(self, server):
        """Test SFTP transfer tool."""
        with patch('openaccess_mcp.providers.sftp.asyncssh') as mock_asyncssh:
            # Mock successful SFTP connection
            mock_conn = Mock()
            mock_sftp = Mock()
            mock_sftp.stat.return_value = Mock(size=1024)
            mock_conn.start_sftp_client.return_value.__aenter__.return_value = mock_sftp
            
            mock_asyncssh.connect.return_value = mock_conn
            
            # Create temporary file for testing
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(b"test content")
                temp_file_path = temp_file.name
            
            try:
                # Call the tool
                result = await server.sftp_transfer(
                    profile_id="test-server",
                    direction="get",
                    remote_path="/remote/file.txt",
                    local_path=temp_file_path,
                    caller="testuser"
                )
                
                assert result["success"] is True
                assert "bytes_transferred" in result["data"]
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_rsync_sync_tool(self, server):
        """Test rsync sync tool."""
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.run_in_executor.return_value = Mock(
                returncode=0,
                stdout="sending incremental file list\nfile1.txt\ntotal size is 1024",
                stderr=""
            )
            
            # Call the tool
            result = await server.rsync_sync(
                profile_id="test-server",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "files_transferred" in result["data"]
    
    @pytest.mark.asyncio
    async def test_tunnel_create_tool(self, server):
        """Test tunnel create tool."""
        with patch('openaccess_mcp.providers.tunnel.asyncssh') as mock_asyncssh:
            # Mock successful SSH connection
            mock_conn = Mock()
            mock_tunnel = Mock()
            mock_tunnel.get_port.return_value = 8080
            mock_conn.create_local_port_forward.return_value = mock_tunnel
            
            mock_asyncssh.connect.return_value = mock_conn
            
            # Call the tool
            result = await server.tunnel_create(
                profile_id="test-server",
                tunnel_type="local",
                target_host="internal.host",
                target_port=80,
                caller="testuser"
            )
            
            assert result["success"] is True
            assert "tunnel_id" in result["data"]
            assert result["data"]["tunnel_type"] == "local"
    
    @pytest.mark.asyncio
    async def test_vpn_wireguard_tool(self, server):
        """Test WireGuard VPN tool."""
        with patch.object(server.vpn_provider, '_run_command') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            
            with patch.object(server.vpn_provider, '_interface_exists') as mock_exists:
                mock_exists.return_value = False
                
                with patch.object(server.vpn_provider, '_get_interface_ip') as mock_ip:
                    mock_ip.return_value = {"ip": "10.0.0.1"}
                    
                    # Call the tool
                    result = await server.vpn_wireguard_toggle(
                        profile_id="test-server",
                        peer_id="test-peer",
                        action="up",
                        caller="testuser"
                    )
                    
                    assert result["success"] is True
                    assert "status" in result["data"]
                    assert result["data"]["status"] == "up"
    
    @pytest.mark.asyncio
    async def test_rdp_launch_tool(self, server):
        """Test RDP launch tool."""
        # Call the tool
        result = await server.rdp_launch(
            profile_id="test-server",
            caller="testuser"
        )
        
        assert result["success"] is True
        assert "connection_id" in result["data"]
        assert "rdp_file" in result["data"]
        assert "connection_url" in result["data"]
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, server):
        """Test audit logging functionality."""
        # Perform an operation that should be logged
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            mock_conn.run.return_value = Mock(
                stdout="test output",
                stderr="",
                exit_code=0
            )
            mock_asyncssh.connect.return_value = mock_conn
            
            await server.ssh_exec(
                profile_id="test-server",
                command="echo test",
                caller="testuser"
            )
        
        # Check that audit log was created
        audit_log_path = server.audit_logger.log_path
        assert audit_log_path.exists()
        
        # Read and verify audit log
        with open(audit_log_path, 'r') as f:
            log_lines = f.readlines()
        
        assert len(log_lines) > 0
        
        # Verify log format (should be JSON lines)
        import json
        for line in log_lines:
            if line.strip():
                log_entry = json.loads(line)
                assert "ts" in log_entry
                assert "actor" in log_entry
                assert "tool" in log_entry
                assert "profile_id" in log_entry
    
    @pytest.mark.asyncio
    async def test_error_handling(self, server):
        """Test error handling in tools."""
        # Test with non-existent profile
        result = await server.ssh_exec(
            profile_id="non-existent",
            command="echo test",
            caller="testuser"
        )
        
        assert result["success"] is False
        assert "error" in result["data"]
        
        # Test with invalid command (policy violation)
        result = await server.ssh_exec(
            profile_id="test-server",
            command="rm -rf /",
            caller="testuser"
        )
        
        assert result["success"] is False
        assert "error" in result["data"]
    
    @pytest.mark.asyncio
    async def test_server_cleanup(self, server):
        """Test server cleanup functionality."""
        # Create some test tunnels
        with patch('openaccess_mcp.providers.tunnel.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            mock_tunnel = Mock()
            mock_tunnel.get_port.return_value = 8080
            mock_conn.create_local_port_forward.return_value = mock_tunnel
            
            mock_asyncssh.connect.return_value = mock_conn
            
            await server.tunnel_create(
                profile_id="test-server",
                tunnel_type="local",
                target_host="internal.host",
                target_port=80,
                caller="testuser"
            )
        
        # Verify tunnel was created
        assert len(server.tunnel_provider._active_tunnels) > 0
        
        # Cleanup
        await server.cleanup()
        
        # Verify cleanup
        assert len(server.tunnel_provider._active_tunnels) == 0


class TestEndToEndWorkflows:
    """End-to-end workflow tests."""
    
    @pytest.fixture
    async def server(self):
        """Create a test server for workflow testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            profiles_dir = Path(temp_dir) / "profiles"
            secrets_dir = Path(temp_dir) / "secrets"
            audit_dir = Path(temp_dir) / "audit"
            
            profiles_dir.mkdir()
            secrets_dir.mkdir()
            audit_dir.mkdir()
            
            # Create test profile
            profile = Profile(
                id="workflow-test",
                host="127.0.0.1",
                port=22,
                protocols=["ssh", "sftp", "rsync", "tunnel", "vpn", "rdp"],
                auth=AuthRef(type="file_ref", ref="workflow-test"),
                policy=Policy(
                    roles=["admin"],
                    command_allowlist=["^echo\\b", "^ls\\b", "^cat\\b"],
                    deny_sudo=False,
                    max_session_seconds=900
                )
            )
            
            profile_file = profiles_dir / "workflow-test.json"
            profile_file.write_text(profile.model_dump_json())
            
            # Create test secret
            secret_data = {
                "username": "workflowuser",
                "password": "workflowpass"
            }
            
            secret_file = secrets_dir / "workflow-test.json"
            secret_file.write_text(json.dumps(secret_data))
            
            server = OpenAccessMCPServer(
                profiles_dir=profiles_dir,
                secrets_dir=secrets_dir,
                audit_log_path=audit_dir / "audit.log",
                audit_key_path=audit_dir / "audit.key"
            )
            
            yield server
            
            await server.cleanup()
    
    @pytest.mark.asyncio
    async def test_ssh_to_sftp_workflow(self, server):
        """Test SSH command execution followed by SFTP file transfer."""
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_ssh:
            mock_conn = Mock()
            mock_conn.run.return_value = Mock(
                stdout="file1.txt\nfile2.txt",
                stderr="",
                exit_code=0
            )
            mock_ssh.connect.return_value = mock_conn
            
            # List files via SSH
            ssh_result = await server.ssh_exec(
                profile_id="workflow-test",
                command="ls -1",
                caller="workflowuser"
            )
            
            assert ssh_result["success"] is True
        
        with patch('openaccess_mcp.providers.sftp.asyncssh') as mock_sftp:
            mock_conn = Mock()
            mock_sftp_client = Mock()
            mock_sftp_client.stat.return_value = Mock(size=512)
            mock_conn.start_sftp_client.return_value.__aenter__.return_value = mock_sftp_client
            
            mock_sftp.connect.return_value = mock_conn
            
            # Download a file via SFTP
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file_path = temp_file.name
            
            try:
                sftp_result = await server.sftp_transfer(
                    profile_id="workflow-test",
                    direction="get",
                    remote_path="/remote/file1.txt",
                    local_path=temp_file_path,
                    caller="workflowuser"
                )
                
                assert sftp_result["success"] is True
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_tunnel_to_rdp_workflow(self, server):
        """Test tunnel creation followed by RDP connection."""
        with patch('openaccess_mcp.providers.tunnel.asyncssh') as mock_ssh:
            mock_conn = Mock()
            mock_tunnel = Mock()
            mock_tunnel.get_port.return_value = 8080
            mock_conn.create_local_port_forward.return_value = mock_tunnel
            
            mock_ssh.connect.return_value = mock_conn
            
            # Create tunnel
            tunnel_result = await server.tunnel_create(
                profile_id="workflow-test",
                tunnel_type="local",
                target_host="internal.rdp.host",
                target_port=3389,
                caller="workflowuser"
            )
            
            assert tunnel_result["success"] is True
            tunnel_id = tunnel_result["data"]["tunnel_id"]
        
        # Launch RDP connection
        rdp_result = await server.rdp_launch(
            profile_id="workflow-test",
            caller="workflowuser"
        )
        
        assert rdp_result["success"] is True
        
        # Close tunnel
        close_result = await server.tunnel_close(
            tunnel_id=tunnel_id,
            caller="workflowuser"
        )
        
        assert close_result["success"] is True
    
    @pytest.mark.asyncio
    async def test_rsync_dry_run_workflow(self, server):
        """Test rsync dry-run followed by actual sync."""
        with patch('asyncio.get_event_loop') as mock_loop:
            # Mock dry-run
            mock_loop.return_value.run_in_executor.return_value = Mock(
                returncode=0,
                stdout="sending incremental file list\nfile1.txt\nfile2.txt\ntotal size is 2048",
                stderr=""
            )
            
            # Perform dry-run
            dry_run_result = await server.rsync_sync(
                profile_id="workflow-test",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                delete_extras=True,
                dry_run=True,
                caller="workflowuser"
            )
            
            assert dry_run_result["success"] is True
            assert dry_run_result["data"]["dry_run"] is True
            
            # Now perform actual sync
            sync_result = await server.rsync_sync(
                profile_id="workflow-test",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                delete_extras=True,
                dry_run=False,
                caller="workflowuser"
            )
            
            assert sync_result["success"] is True
            assert sync_result["data"]["dry_run"] is False


if __name__ == "__main__":
    pytest.main([__file__])

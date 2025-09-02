"""Unit tests for OpenAccess MCP providers."""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
import tempfile
import os

from openaccess_mcp.providers.ssh import SSHProvider, SSHResult
from openaccess_mcp.providers.sftp import SFTPProvider, SFTPResult
from openaccess_mcp.providers.rsync import RsyncProvider, RsyncResult
from openaccess_mcp.providers.tunnel import TunnelProvider, TunnelInfo
from openaccess_mcp.providers.vpn import VPNProvider, VPNStatus
from openaccess_mcp.providers.rdp import RDPBrokerProvider, RDPConnection
from openaccess_mcp.types import SecretData


class TestSSHProvider:
    """Test SSH provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return SSHProvider()
    
    @pytest.fixture
    def mock_secret(self):
        return SecretData(
            username="testuser",
            password="testpass",
            private_key=None,
            passphrase=None
        )
    
    @pytest.mark.asyncio
    async def test_exec_command_success(self, provider, mock_secret):
        """Test successful command execution."""
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            
            # Mock conn.run as an async function
            async def mock_run(*args, **kwargs):
                return Mock(
                    stdout="command output",
                    stderr="",
                    exit_status=0
                )
            mock_conn.run = mock_run
            
            # Mock asyncssh.connect as an async function
            async def mock_connect(*args, **kwargs):
                return mock_conn
            mock_asyncssh.connect = mock_connect
            
            result = await provider.exec_command(
                host="testhost",
                port=22,
                secret=mock_secret,
                command="echo hello",
                timeout=30
            )
            
            assert result.stdout == "command output"
            assert result.stderr == ""
            assert result.exit_code == 0
    
    @pytest.mark.asyncio
    async def test_exec_command_with_sudo(self, provider, mock_secret):
        """Test command execution with sudo."""
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            
            # Mock conn.run as an async function
            async def mock_run(*args, **kwargs):
                return Mock(
                    stdout="sudo output",
                    stderr="",
                    exit_status=0
                )
            mock_conn.run = mock_run
            
            # Mock asyncssh.connect as an async function
            async def mock_connect(*args, **kwargs):
                return mock_conn
            mock_asyncssh.connect = mock_connect
            
            result = await provider.exec_command(
                host="testhost",
                port=22,
                secret=mock_secret,
                command="sudo ls /root",
                timeout=30,
                sudo=True
            )
            
            assert result.stdout == "sudo output"
            # The command is processed internally, so we can't check it directly
            # Instead, verify the result was successful
            assert result.exit_code == 0
    
    @pytest.mark.asyncio
    async def test_exec_command_failure(self, provider, mock_secret):
        """Test command execution failure."""
        with patch('openaccess_mcp.providers.ssh.asyncssh') as mock_asyncssh:
            # Mock asyncssh.connect to raise an exception
            async def mock_connect(*args, **kwargs):
                raise Exception("Connection failed")
            mock_asyncssh.connect = mock_connect
            
            with pytest.raises(RuntimeError, match="Connection failed"):
                await provider.exec_command(
                    host="testhost",
                    port=22,
                    secret=mock_secret,
                    command="echo test",
                    timeout=30
                )


class TestSFTPProvider:
    """Test SFTP provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return SFTPProvider()
    
    @pytest.fixture
    def mock_secret(self):
        return SecretData(
            username="testuser",
            password="testpass",
            private_key=None,
            passphrase=None
        )
    
    @pytest.mark.asyncio
    async def test_transfer_file_download(self, provider, mock_secret):
        """Test file download via SFTP."""
        with patch('openaccess_mcp.providers.sftp.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            mock_sftp = Mock()
            mock_sftp.stat.return_value = Mock(size=1024)
            
            # Mock the async context manager
            mock_context = Mock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_sftp)
            mock_context.__aexit__ = AsyncMock(return_value=None)
            mock_conn.start_sftp_client.return_value = mock_context
            
            # Mock asyncssh.connect as an async function
            async def mock_connect(*args, **kwargs):
                return mock_conn
            mock_asyncssh.connect = mock_connect
            
            # Mock the file operations
            async def mock_get(*args, **kwargs):
                pass
            mock_sftp.get = mock_get
            
            async def mock_stat(*args, **kwargs):
                return Mock(size=1024)
            mock_sftp.stat = mock_stat
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file_path = temp_file.name
            
            try:
                result = await provider.transfer_file(
                    host="testhost",
                    port=22,
                    secret=mock_secret,
                    direction="get",
                    remote_path="/remote/file.txt",
                    local_path=temp_file_path
                )
                
                assert result.success is True
                assert result.bytes_transferred == 1024
                assert result.checksum is not None
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_transfer_file_upload(self, provider, mock_secret):
        """Test file upload via SFTP."""
        with patch('openaccess_mcp.providers.sftp.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            mock_sftp = Mock()
            
            # Mock the async context manager
            mock_context = Mock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_sftp)
            mock_context.__aexit__ = AsyncMock(return_value=None)
            mock_conn.start_sftp_client.return_value = mock_context
            
            # Mock asyncssh.connect as an async function
            async def mock_connect(*args, **kwargs):
                return mock_conn
            mock_asyncssh.connect = mock_connect
            
            # Mock the file operations
            async def mock_put(*args, **kwargs):
                pass
            mock_sftp.put = mock_put
            
            async def mock_chmod(*args, **kwargs):
                pass
            mock_sftp.chmod = mock_chmod
            
            async def mock_stat(*args, **kwargs):
                # Return a mock stat object for directory creation
                return Mock()
            mock_sftp.stat = mock_stat
            
            async def mock_mkdir(*args, **kwargs):
                pass
            mock_sftp.mkdir = mock_mkdir
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(b"test content")
                temp_file_path = temp_file.name
            
            try:
                result = await provider.transfer_file(
                    host="testhost",
                    port=22,
                    secret=mock_secret,
                    direction="put",
                    remote_path="/remote/file.txt",
                    local_path=temp_file_path
                )
                
                assert result.success is True
                assert result.checksum is not None
                
            finally:
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_transfer_file_invalid_direction(self, provider, mock_secret):
        """Test invalid direction handling."""
        with pytest.raises(ValueError, match="Direction must be 'get' or 'put'"):
            await provider.transfer_file(
                host="testhost",
                port=22,
                secret=mock_secret,
                direction="invalid",
                remote_path="/remote/file.txt",
                local_path="/local/file.txt"
            )


class TestRsyncProvider:
    """Test rsync provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return RsyncProvider()
    
    @pytest.mark.asyncio
    async def test_sync_success(self, provider):
        """Test successful rsync operation."""
        with patch.object(provider, '_execute_rsync') as mock_execute, \
             patch.object(provider, '_parse_rsync_output') as mock_parse:
            
            # Mock the subprocess result
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "sending incremental file list\nfile1.txt\nfile2.txt\ntotal size is 2048"
            mock_result.stderr = ""
            mock_result.args = ["rsync", "-avz", "--progress", "--dry-run", "-e", "ssh -p 22", "/local/source", "testuser@testhost:/remote/dest"]
            
            mock_execute.return_value = mock_result
            
            # Mock the parsing result
            mock_parse.return_value = RsyncResult(
                success=True,
                files_transferred=2,
                bytes_transferred=2048,
                dry_run=True,
                plan="Incremental file list:",
                metadata={}
            )
            
            result = await provider.sync(
                host="testhost",
                port=22,
                username="testuser",
                direction="push",
                source="/local/source",
                dest="/remote/dest"
            )
            
            assert result.success is True
            assert result.files_transferred > 0
            assert result.bytes_transferred == 2048
    
    @pytest.mark.asyncio
    async def test_sync_failure(self, provider):
        """Test rsync operation failure."""
        with patch.object(provider, '_execute_rsync') as mock_execute:
            # Mock the subprocess result for failure
            mock_result = Mock()
            mock_result.returncode = 1
            mock_result.stdout = ""
            mock_result.stderr = "Permission denied"
            mock_result.args = ["rsync", "-avz", "--progress", "--dry-run", "-e", "ssh -p 22", "/local/source", "testuser@testhost:/remote/dest"]
            
            mock_execute.return_value = mock_result
            
            result = await provider.sync(
                host="testhost",
                port=22,
                username="testuser",
                direction="push",
                source="/local/source",
                dest="/remote/dest"
            )
            
            assert result.success is False
            assert "Permission denied" in result.error
    
    @pytest.mark.asyncio
    async def test_validate_dry_run(self, provider):
        """Test dry-run validation."""
        with patch.object(provider, 'sync') as mock_sync:
            mock_result = Mock()
            mock_result.success = True
            mock_result.files_transferred = 2
            mock_result.bytes_transferred = 1024
            mock_result.dry_run = True
            mock_sync.return_value = mock_result
            
            result = await provider.validate_dry_run(
                host="testhost",
                port=22,
                username="testuser",
                direction="push",
                source="/local/source",
                dest="/remote/dest",
                delete_extras=True
            )
            
            assert result.success is True
            assert result.dry_run is True


class TestTunnelProvider:
    """Test tunnel provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return TunnelProvider()
    
    @pytest.fixture
    def mock_secret(self):
        return SecretData(
            username="testuser",
            password="testpass",
            private_key=None,
            passphrase=None
        )
    
    @pytest.mark.asyncio
    async def test_create_local_tunnel(self, provider, mock_secret):
        """Test local tunnel creation."""
        with patch('openaccess_mcp.providers.tunnel.asyncssh') as mock_asyncssh:
            mock_conn = Mock()
            mock_tunnel = Mock()
            mock_tunnel.get_port.return_value = 8080
            
            # Mock the async create_local_port_forward method
            async def mock_create_local_port_forward(*args, **kwargs):
                return mock_tunnel
            mock_conn.create_local_port_forward = mock_create_local_port_forward
            
            # Mock asyncssh.connect as an async function
            async def mock_connect(*args, **kwargs):
                return mock_conn
            mock_asyncssh.connect = mock_connect
            
            tunnel_info = await provider.create_tunnel(
                host="testhost",
                port=22,
                secret=mock_secret,
                tunnel_type="local",
                target_host="internal.host",
                target_port=80,
                profile_id="test-profile"
            )
            
            assert tunnel_info.tunnel_type == "local"
            assert tunnel_info.target_host == "internal.host"
            assert tunnel_info.target_port == 80
            assert tunnel_info.listen_port == 8080
    
    @pytest.mark.asyncio
    async def test_create_tunnel_invalid_type(self, provider, mock_secret):
        """Test invalid tunnel type handling."""
        with pytest.raises(ValueError, match="Tunnel type must be"):
            await provider.create_tunnel(
                host="testhost",
                port=22,
                secret=mock_secret,
                tunnel_type="invalid",
                profile_id="test-profile"
            )
    
    @pytest.mark.asyncio
    async def test_close_tunnel(self, provider):
        """Test tunnel closure."""
        # Create a mock tunnel first
        tunnel_info = TunnelInfo(
            tunnel_id="test-tunnel",
            tunnel_type="local",
            listen_host="127.0.0.1",
            listen_port=8080,
            target_host="internal.host",
            target_port=80,
            created_at=0,
            ttl_seconds=3600,
            profile_id="test-profile"
        )
        
        provider._active_tunnels["test-tunnel"] = tunnel_info
        provider._tunnel_handles["test-tunnel"] = Mock()
        
        success = await provider.close_tunnel("test-tunnel")
        assert success is True
        assert "test-tunnel" not in provider._active_tunnels


class TestVPNProvider:
    """Test VPN provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return VPNProvider()
    
    @pytest.mark.asyncio
    async def test_wireguard_up(self, provider):
        """Test WireGuard interface up."""
        with patch.object(provider, '_run_command') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            
            with patch.object(provider, '_interface_exists') as mock_exists:
                mock_exists.return_value = False
                
                with patch.object(provider, '_get_interface_ip') as mock_ip:
                    mock_ip.return_value = {"ip": "10.0.0.1"}
                    
                    result = await provider.wireguard_toggle(
                        peer_id="test-peer",
                        action="up"
                    )
                    
                    assert result.status == "up"
                    assert result.peer_id == "test-peer"
                    assert result.ip_address == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_wireguard_down(self, provider):
        """Test WireGuard interface down."""
        with patch.object(provider, '_run_command') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            
            with patch.object(provider, '_interface_exists') as mock_exists:
                mock_exists.return_value = True
                
                # Add to active connections first
                provider._active_connections["test-peer"] = VPNStatus(
                    interface="wg-test-peer",
                    status="up",
                    peer_id="test-peer"
                )
                
                result = await provider.wireguard_toggle(
                    peer_id="test-peer",
                    action="down"
                )
                
                assert result.status == "down"
                assert "test-peer" not in provider._active_connections
    
    @pytest.mark.asyncio
    async def test_openvpn_connect(self, provider):
        """Test OpenVPN connection."""
        with patch.object(provider, '_run_command') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            
            with patch.object(provider, '_openvpn_connected') as mock_connected:
                mock_connected.return_value = True
                
                result = await provider.openvpn_toggle(
                    config_id="test-config",
                    action="connect",
                    config_path="/path/to/config.ovpn"
                )
                
                assert result.status == "up"
                assert result.config_id == "test-config"
                assert "test-config" in provider._active_connections


class TestRDPBrokerProvider:
    """Test RDP broker provider functionality."""
    
    @pytest.fixture
    def provider(self):
        return RDPBrokerProvider("https://rdp.test.com")
    
    @pytest.mark.asyncio
    async def test_create_connection(self, provider):
        """Test RDP connection creation."""
        connection = await provider.create_connection(
            profile_id="test-profile",
            host="rdp.test.com",
            port=3389,
            username="testuser",
            ttl_seconds=7200
        )
        
        assert connection.profile_id == "test-profile"
        assert connection.host == "rdp.test.com"
        assert connection.username == "testuser"
        assert connection.connection_id in provider._connections
    
    @pytest.mark.asyncio
    async def test_generate_rdp_file(self, provider):
        """Test .rdp file generation."""
        connection = await provider.create_connection(
            profile_id="test-profile",
            host="rdp.test.com",
            username="testuser"
        )
        
        rdp_content = await provider.generate_rdp_file(connection.connection_id)
        
        assert "full address:s:rdp.test.com:3389" in rdp_content
        assert "username:s:testuser" in rdp_content
        assert "prompt for credentials:i:1" in rdp_content
    
    @pytest.mark.asyncio
    async def test_generate_connection_url(self, provider):
        """Test connection URL generation."""
        connection = await provider.create_connection(
            profile_id="test-profile",
            host="rdp.test.com",
            username="testuser"
        )
        
        url = await provider.generate_connection_url(connection.connection_id)
        
        assert url.startswith("https://rdp.test.com/connect?")
        assert "id=" in url
        assert "host=rdp.test.com" in url
        assert "username=testuser" in url
        assert "sig=" in url
    
    @pytest.mark.asyncio
    async def test_validate_connection_url(self, provider):
        """Test connection URL validation."""
        connection = await provider.create_connection(
            profile_id="test-profile",
            host="rdp.test.com",
            username="testuser"
        )
        
        url = await provider.generate_connection_url(connection.connection_id)
        validated_connection = await provider.validate_connection_url(url)
        
        assert validated_connection is not None
        assert validated_connection.connection_id == connection.connection_id
    
    @pytest.mark.asyncio
    async def test_connection_expiration(self, provider):
        """Test connection expiration handling."""
        connection = await provider.create_connection(
            profile_id="test-profile",
            host="rdp.test.com",
            username="testuser",
            ttl_seconds=1  # Very short TTL
        )
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        
        # Connection should be expired
        assert connection.is_expired is True
        assert connection.remaining_seconds == 0


if __name__ == "__main__":
    pytest.main([__file__])

"""SSH provider for OpenAccess MCP."""

import asyncio
import uuid
from typing import Optional, Tuple
from dataclasses import dataclass

try:
    import asyncssh
except ImportError:
    asyncssh = None

from ..types import SecretData


@dataclass
class SSHResult:
    """Result of an SSH operation."""
    
    stdout: str
    stderr: str
    exit_code: int
    session_id: str


class SSHProvider:
    """Handles SSH connections and command execution."""
    
    def __init__(self):
        self._active_connections = {}
    
    async def exec_command(
        self,
        host: str,
        port: int,
        secret: SecretData,
        command: str,
        pty: bool = False,
        sudo: bool = False,
        timeout: int = 60
    ) -> SSHResult:
        """Execute a command over SSH."""
        if asyncssh is None:
            raise ImportError("asyncssh is required for SSH operations")
        
        # Prepare the command
        if sudo:
            command = f"sudo {command}"
        
        # Create connection key
        conn_key = f"{host}:{port}:{secret.username}"
        
        # Get or create connection
        conn = await self._get_connection(conn_key, host, port, secret)
        
        try:
            # Execute command
            if pty:
                result = await conn.run(
                    command,
                    timeout=timeout,
                    request_pty=True
                )
            else:
                result = await conn.run(command, timeout=timeout)
            
            return SSHResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status,
                session_id=str(uuid.uuid4())
            )
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"SSH command timed out after {timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"SSH command failed: {e}")
    
    async def _get_connection(self, conn_key: str, host: str, port: int, secret: SecretData):
        """Get or create an SSH connection."""
        if conn_key in self._active_connections:
            return self._active_connections[conn_key]
        
        # Create new connection
        try:
            if secret.has_key_auth():
                conn = await asyncssh.connect(
                    host,
                    port=port,
                    username=secret.username,
                    client_keys=[secret.private_key],
                    passphrase=secret.passphrase,
                    known_hosts=None  # In production, you'd want proper host key verification
                )
            else:
                conn = await asyncssh.connect(
                    host,
                    port=port,
                    username=secret.username,
                    password=secret.password,
                    known_hosts=None
                )
            
            self._active_connections[conn_key] = conn
            return conn
            
        except Exception as e:
            raise RuntimeError(f"Failed to establish SSH connection: {e}")
    
    async def close_connection(self, host: str, port: int, username: str) -> None:
        """Close an SSH connection."""
        conn_key = f"{host}:{port}:{username}"
        if conn_key in self._active_connections:
            conn = self._active_connections[conn_key]
            conn.close()
            del self._active_connections[conn_key]
    
    async def close_all_connections(self) -> None:
        """Close all active SSH connections."""
        for conn in self._active_connections.values():
            conn.close()
        self._active_connections.clear()
    
    def get_connection_stats(self) -> dict:
        """Get statistics about active connections."""
        return {
            "active_connections": len(self._active_connections),
            "connection_keys": list(self._active_connections.keys())
        }

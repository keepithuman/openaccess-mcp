"""SFTP provider for OpenAccess MCP."""

import asyncio
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

try:
    import asyncssh
except ImportError:
    asyncssh = None

from ..types import SecretData


@dataclass
class SFTPResult:
    """Result of an SFTP operation."""
    
    success: bool
    bytes_transferred: int
    checksum: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class SFTPProvider:
    """Handles SFTP file operations using asyncssh."""
    
    def __init__(self):
        self._active_connections = {}
    
    async def transfer_file(
        self,
        host: str,
        port: int,
        secret: SecretData,
        direction: str,
        remote_path: str,
        local_path: str,
        checksum: Optional[str] = None,
        create_dirs: bool = True,
        mode: Optional[str] = None
    ) -> SFTPResult:
        """Transfer a file via SFTP."""
        if asyncssh is None:
            raise ImportError("asyncssh is required for SFTP operations")
        
        # Validate direction
        if direction not in ["get", "put"]:
            raise ValueError("Direction must be 'get' or 'put'")
        
        # Create connection key
        conn_key = f"{host}:{port}:{secret.username}"
        
        # Get or create connection
        conn = await self._get_connection(conn_key, host, port, secret)
        
        try:
            if direction == "get":
                return await self._download_file(
                    conn, remote_path, local_path, checksum, create_dirs
                )
            else:
                return await self._upload_file(
                    conn, local_path, remote_path, checksum, create_dirs, mode
                )
                
        except Exception as e:
            return SFTPResult(
                success=False,
                bytes_transferred=0,
                error=str(e)
            )
    
    async def _download_file(
        self,
        conn,
        remote_path: str,
        local_path: str,
        checksum: Optional[str] = None,
        create_dirs: bool = True
    ) -> SFTPResult:
        """Download a file from remote to local."""
        try:
            # Ensure local directory exists
            local_file = Path(local_path)
            if create_dirs:
                local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Get file info
            async with conn.start_sftp_client() as sftp:
                stat = await sftp.stat(remote_path)
                file_size = stat.size
                
                # Download file
                await sftp.get(remote_path, local_path)
                
                # Verify checksum if provided
                if checksum:
                    local_checksum = await self._calculate_file_checksum(local_path)
                    if local_checksum != checksum:
                        return SFTPResult(
                            success=False,
                            bytes_transferred=file_size,
                            error=f"Checksum mismatch: expected {checksum}, got {local_checksum}"
                        )
                
                return SFTPResult(
                    success=True,
                    bytes_transferred=file_size,
                    checksum=await self._calculate_file_checksum(local_path),
                    metadata={
                        "remote_path": remote_path,
                        "local_path": str(local_path),
                        "file_size": file_size
                    }
                )
                
        except Exception as e:
            return SFTPResult(
                success=False,
                bytes_transferred=0,
                error=f"Download failed: {e}"
            )
    
    async def _upload_file(
        self,
        conn,
        local_path: str,
        remote_path: str,
        checksum: Optional[str] = None,
        create_dirs: bool = True,
        mode: Optional[str] = None
    ) -> SFTPResult:
        """Upload a file from local to remote."""
        try:
            local_file = Path(local_path)
            if not local_file.exists():
                return SFTPResult(
                    success=False,
                    bytes_transferred=0,
                    error=f"Local file not found: {local_path}"
                )
            
            file_size = local_file.stat().st_size
            
            async with conn.start_sftp_client() as sftp:
                # Create remote directory if needed
                if create_dirs:
                    remote_dir = Path(remote_path).parent
                    await self._ensure_remote_directory(sftp, str(remote_dir))
                
                # Upload file
                await sftp.put(local_path, remote_path)
                
                # Set mode if specified
                if mode:
                    try:
                        mode_int = int(mode, 8)
                        await sftp.chmod(remote_path, mode_int)
                    except ValueError:
                        return SFTPResult(
                            success=False,
                            bytes_transferred=file_size,
                            error=f"Invalid mode format: {mode}"
                        )
                
                # Verify checksum if provided
                if checksum:
                    remote_checksum = await self._calculate_remote_checksum(sftp, remote_path)
                    if remote_checksum != checksum:
                        return SFTPResult(
                            success=False,
                            bytes_transferred=file_size,
                            error=f"Checksum mismatch: expected {checksum}, got {remote_checksum}"
                        )
                
                return SFTPResult(
                    success=True,
                    bytes_transferred=file_size,
                    checksum=await self._calculate_file_checksum(local_path),
                    metadata={
                        "local_path": local_path,
                        "remote_path": remote_path,
                        "file_size": file_size,
                        "mode": mode
                    }
                )
                
        except Exception as e:
            return SFTPResult(
                success=False,
                bytes_transferred=0,
                error=f"Upload failed: {e}"
            )
    
    async def _ensure_remote_directory(self, sftp, remote_dir: str) -> None:
        """Ensure remote directory exists, creating it if necessary."""
        try:
            await sftp.stat(remote_dir)
        except FileNotFoundError:
            # Create directory recursively
            parts = remote_dir.split('/')
            current = ""
            for part in parts:
                if part:
                    current = f"{current}/{part}" if current else part
                    try:
                        await sftp.stat(current)
                    except FileNotFoundError:
                        await sftp.mkdir(current)
    
    async def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a local file."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._calculate_checksum_sync, file_path)
    
    def _calculate_checksum_sync(self, file_path: str) -> str:
        """Synchronous checksum calculation."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return f"sha256:{hash_sha256.hexdigest()}"
    
    async def _calculate_remote_checksum(self, sftp, remote_path: str) -> str:
        """Calculate SHA256 checksum of a remote file."""
        # Download to temporary location and calculate checksum
        temp_path = f"/tmp/temp_checksum_{hash(remote_path) % 10000}"
        try:
            await sftp.get(remote_path, temp_path)
            checksum = await self._calculate_file_checksum(temp_path)
            # Clean up temp file
            os.unlink(temp_path)
            return checksum
        except Exception:
            # Clean up temp file if it exists
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            raise
    
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
                    known_hosts=None
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
        """Close an SFTP connection."""
        conn_key = f"{host}:{port}:{username}"
        if conn_key in self._active_connections:
            conn = self._active_connections[conn_key]
            conn.close()
            del self._active_connections[conn_key]
    
    async def close_all_connections(self) -> None:
        """Close all active SFTP connections."""
        for conn in self._active_connections.values():
            conn.close()
        self._active_connections.clear()
    
    def get_connection_stats(self) -> dict:
        """Get statistics about active connections."""
        return {
            "active_connections": len(self._active_connections),
            "connection_keys": list(self._active_connections.keys())
        }

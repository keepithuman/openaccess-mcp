"""Tunnel provider for OpenAccess MCP."""

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

try:
    import asyncssh
except ImportError:
    asyncssh = None

from ..types import SecretData


@dataclass
class TunnelInfo:
    """Information about an active tunnel."""
    
    tunnel_id: str
    tunnel_type: str
    listen_host: str
    listen_port: int
    target_host: Optional[str]
    target_port: Optional[int]
    created_at: float
    ttl_seconds: int
    profile_id: str
    status: str = "active"
    
    @property
    def expires_at(self) -> float:
        """When the tunnel expires."""
        return self.created_at + self.ttl_seconds
    
    @property
    def is_expired(self) -> bool:
        """Whether the tunnel has expired."""
        return time.time() > self.expires_at
    
    @property
    def remaining_seconds(self) -> int:
        """Seconds remaining before expiration."""
        remaining = self.expires_at - time.time()
        return max(0, int(remaining))


class TunnelProvider:
    """Handles SSH tunnel operations."""
    
    def __init__(self):
        """Initialize the tunnel provider."""
        self._active_tunnels: Dict[str, TunnelInfo] = {}
        self._tunnel_handles: Dict[str, Any] = {}  # SSH tunnel handles
        self._cleanup_task: Optional[asyncio.Task] = None
        # Don't start cleanup task in constructor - let it be started when needed
    
    async def start_cleanup_task(self):
        """Start the background cleanup task if not already running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_tunnels())
    
    def _start_cleanup_task(self):
        """Start the background cleanup task (synchronous version for backward compatibility)."""
        # This method is kept for backward compatibility but doesn't start the task
        # The task should be started explicitly when needed
        pass
    
    async def create_tunnel(
        self,
        host: str,
        port: int,
        secret: SecretData,
        tunnel_type: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        ttl_seconds: int = 3600,
        profile_id: str = "unknown"
    ) -> TunnelInfo:
        """Create an SSH tunnel."""
        if asyncssh is None:
            raise ImportError("asyncssh is required for tunnel operations")
        
        # Validate tunnel type
        if tunnel_type not in ["local", "remote", "dynamic"]:
            raise ValueError("Tunnel type must be 'local', 'remote', or 'dynamic'")
        
        # Validate parameters for tunnel type
        if tunnel_type in ["local", "remote"]:
            if not target_host or not target_port:
                raise ValueError(f"{tunnel_type} tunnels require target_host and target_port")
        
        # Create tunnel ID
        tunnel_id = str(uuid.uuid4())
        
        # Create tunnel info
        tunnel_info = TunnelInfo(
            tunnel_id=tunnel_id,
            tunnel_type=tunnel_type,
            listen_host=listen_host,
            listen_port=listen_port,
            target_host=target_host,
            target_port=target_port,
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
            profile_id=profile_id
        )
        
        try:
            # Establish SSH connection
            conn = await self._get_connection(host, port, secret)
            
            # Create tunnel based on type
            if tunnel_type == "local":
                tunnel_handle = await self._create_local_tunnel(
                    conn, listen_host, listen_port, target_host, target_port
                )
            elif tunnel_type == "remote":
                tunnel_handle = await self._create_remote_tunnel(
                    conn, listen_host, listen_port, target_host, target_port
                )
            else:  # dynamic
                tunnel_handle = await self._create_dynamic_tunnel(
                    conn, listen_host, listen_port
                )
            
            # Store tunnel info and handle
            self._active_tunnels[tunnel_id] = tunnel_info
            self._tunnel_handles[tunnel_id] = tunnel_handle
            
            # Update listen port if it was auto-assigned
            if listen_port == 0:
                tunnel_info.listen_port = tunnel_handle.get_port()
            
            return tunnel_info
            
        except Exception as e:
            # Clean up on failure
            self._active_tunnels.pop(tunnel_id, None)
            self._tunnel_handles.pop(tunnel_id, None)
            raise RuntimeError(f"Failed to create tunnel: {e}")
    
    async def _create_local_tunnel(
        self,
        conn,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int
    ):
        """Create a local port forward tunnel."""
        return await conn.create_local_port_forward(
            listen_host, listen_port, target_host, target_port
        )
    
    async def _create_remote_tunnel(
        self,
        conn,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int
    ):
        """Create a remote port forward tunnel."""
        return await conn.create_remote_port_forward(
            listen_host, listen_port, target_host, target_port
        )
    
    async def _create_dynamic_tunnel(
        self,
        conn,
        listen_host: str,
        listen_port: int
    ):
        """Create a dynamic SOCKS tunnel."""
        return await conn.create_local_port_forward(
            listen_host, listen_port, None, None
        )
    
    async def close_tunnel(self, tunnel_id: str) -> bool:
        """Close an SSH tunnel."""
        if tunnel_id not in self._active_tunnels:
            return False
        
        try:
            # Close tunnel handle
            if tunnel_id in self._tunnel_handles:
                tunnel_handle = self._tunnel_handles[tunnel_id]
                tunnel_handle.close()
                del self._tunnel_handles[tunnel_id]
            
            # Remove tunnel info
            del self._active_tunnels[tunnel_id]
            
            return True
            
        except Exception:
            return False
    
    async def close_all_tunnels(self) -> int:
        """Close all active tunnels."""
        closed_count = 0
        tunnel_ids = list(self._active_tunnels.keys())
        
        for tunnel_id in tunnel_ids:
            if await self.close_tunnel(tunnel_id):
                closed_count += 1
        
        return closed_count
    
    def get_tunnel_info(self, tunnel_id: str) -> Optional[TunnelInfo]:
        """Get information about a specific tunnel."""
        return self._active_tunnels.get(tunnel_id)
    
    def list_tunnels(self, profile_id: Optional[str] = None) -> List[TunnelInfo]:
        """List all active tunnels, optionally filtered by profile."""
        tunnels = list(self._active_tunnels.values())
        
        if profile_id:
            tunnels = [t for t in tunnels if t.profile_id == profile_id]
        
        return sorted(tunnels, key=lambda t: t.created_at, reverse=True)
    
    def get_tunnel_stats(self) -> Dict[str, Any]:
        """Get statistics about active tunnels."""
        now = time.time()
        active_tunnels = [t for t in self._active_tunnels.values() if not t.is_expired]
        expired_tunnels = [t for t in self._active_tunnels.values() if t.is_expired]
        
        return {
            "total_tunnels": len(self._active_tunnels),
            "active_tunnels": len(active_tunnels),
            "expired_tunnels": len(expired_tunnels),
            "tunnel_types": {
                t.tunnel_type: len([t2 for t2 in active_tunnels if t2.tunnel_type == t.tunnel_type])
                for t in active_tunnels
            },
            "profiles": {
                t.profile_id: len([t2 for t2 in active_tunnels if t2.profile_id == t.profile_id])
                for t in active_tunnels
            }
        }
    
    async def _get_connection(self, host: str, port: int, secret: SecretData):
        """Get or create an SSH connection."""
        # For now, create a new connection for each tunnel
        # In production, you might want connection pooling
        if asyncssh is None:
            raise ImportError("asyncssh is required for tunnel operations")

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
            
            return conn
            
        except Exception as e:
            raise RuntimeError(f"Failed to establish SSH connection: {e}")
    
    async def _cleanup_expired_tunnels(self) -> None:
        """Background task to clean up expired tunnels."""
        while True:
            try:
                # Find expired tunnels
                expired_tunnels = [
                    tunnel_id for tunnel_id, tunnel_info in self._active_tunnels.items()
                    if tunnel_info.is_expired
                ]
                
                # Close expired tunnels
                for tunnel_id in expired_tunnels:
                    await self.close_tunnel(tunnel_id)
                
                # Sleep for a bit before next check
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error and continue
                await asyncio.sleep(60)
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    @asynccontextmanager
    async def tunnel_context(self, tunnel_info: TunnelInfo):
        """Context manager for automatic tunnel cleanup."""
        try:
            yield tunnel_info
        finally:
            await self.close_tunnel(tunnel_info.tunnel_id)

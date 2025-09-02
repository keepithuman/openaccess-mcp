"""RDP broker provider for OpenAccess MCP."""

import asyncio
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass
class RDPConnection:
    """RDP connection information."""
    
    connection_id: str
    profile_id: str
    host: str
    port: int
    username: str
    domain: Optional[str] = None
    gateway: Optional[str] = None
    created_at: float = None
    expires_at: float = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.expires_at is None:
            self.expires_at = self.created_at + 3600  # 1 hour default
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def is_expired(self) -> bool:
        """Whether the connection has expired."""
        return time.time() > self.expires_at
    
    @property
    def remaining_seconds(self) -> int:
        """Seconds remaining before expiration."""
        remaining = self.expires_at - time.time()
        return max(0, int(remaining))


class RDPBrokerProvider:
    """Handles RDP connection brokering."""
    
    def __init__(self, base_url: str):
        """Initialize the RDP broker provider."""
        self.base_url = base_url.rstrip('/')
        self._connections: Dict[str, RDPConnection] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        # Don't start cleanup task in constructor - let it be started when needed
    
    async def start_cleanup_task(self):
        """Start the background cleanup task if not already running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_connections())
    
    def _start_cleanup_task(self):
        """Start the background cleanup task (synchronous version for backward compatibility)."""
        # This method is kept for backward compatibility but doesn't start the task
        # The task should be started explicitly when needed
        pass
    
    async def create_connection(
        self,
        profile_id: str,
        host: str,
        port: int = 3389,
        username: str = "",
        domain: Optional[str] = None,
        gateway: Optional[str] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> RDPConnection:
        """Create a new RDP connection."""
        # Generate unique connection ID
        connection_id = self._generate_connection_id()
        
        # Create connection object
        connection = RDPConnection(
            connection_id=connection_id,
            profile_id=profile_id,
            host=host,
            port=port,
            username=username,
            domain=domain,
            gateway=gateway,
            expires_at=time.time() + ttl_seconds,
            metadata=metadata or {}
        )
        
        # Store connection
        self._connections[connection_id] = connection
        
        return connection
    
    async def get_connection(self, connection_id: str) -> Optional[RDPConnection]:
        """Get connection by ID."""
        connection = self._connections.get(connection_id)
        
        if connection and connection.is_expired:
            # Remove expired connection
            del self._connections[connection_id]
            return None
        
        return connection
    
    async def list_connections(self, profile_id: Optional[str] = None) -> List[RDPConnection]:
        """List active connections, optionally filtered by profile."""
        connections = list(self._connections.values())
        
        # Filter out expired connections
        active_connections = [c for c in connections if not c.is_expired]
        
        # Filter by profile if specified
        if profile_id:
            active_connections = [c for c in active_connections if c.profile_id == profile_id]
        
        return sorted(active_connections, key=lambda c: c.created_at, reverse=True)
    
    async def revoke_connection(self, connection_id: str) -> bool:
        """Revoke a connection before expiration."""
        if connection_id in self._connections:
            del self._connections[connection_id]
            return True
        return False
    
    async def generate_rdp_file(self, connection_id: str) -> str:
        """Generate .rdp file content for a connection."""
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found or expired")
        
        # Generate .rdp file content
        rdp_content = [
            f"full address:s:{connection.host}:{connection.port}",
            f"username:s:{connection.username}",
        ]
        
        if connection.domain:
            rdp_content.append(f"domain:s:{connection.domain}")
        
        if connection.gateway:
            rdp_content.append(f"gatewayhostname:s:{connection.gateway}")
            rdp_content.append("gatewayusagemethod:i:2")
        
        # Add security settings
        rdp_content.extend([
            "prompt for credentials:i:1",
            "promptcredentialonce:i:0",
            "authentication level:i:2",
            "smart sizing:i:1",
            "redirectclipboard:i:1",
            "redirectprinters:i:0",
            "redirectcomports:i:0",
            "redirectsmartcards:i:0",
            "redirectdrives:i:0",
            "redirectwebauthn:i:1",
            "audiocapturemode:i:0",
            "videoplaybackmode:i:1",
            "connection type:i:7",
            "networkautodetect:i:1",
            "bandwidthautodetect:i:1",
            "displayconnectionbar:i:1",
            "pinconnectionbar:i:0",
            "use multimon:i:0",
            "selectedmonitors:s:",
            "use redirection server name:i:0",
            "loadbalanceinfo:s:",
            "prevent server wallpaper:i:1",
            "prevent server desktop composition:i:0",
            "prevent server font smoothing:i:0",
            "prevent server cursor blinking:i:0",
            "prevent server cursor shadow:i:0",
            "prevent server drawing desktop wallpaper:i:0",
            "prevent server full window drag:i:0",
            "prevent server menu animations:i:0",
            "prevent server themes:i:0",
            "prevent server cursor setting:i:0",
            "bitmapcachepersistenable:i:1",
            "bitmapcachesize:i:1500",
            "audiomode:i:0",
            "redirectposdevices:i:0",
            "redirectdirectx:i:1",
            "autoreconnection enabled:i:1",
            "autoreconnection max retry count:i:20",
            "compression:i:1",
            "keyboardhook:i:2",
            "audiocapturemode:i:0",
            "videoplaybackmode:i:1",
            "connection type:i:7",
            "networkautodetect:i:1",
            "bandwidthautodetect:i:1",
            "displayconnectionbar:i:1",
            "pinconnectionbar:i:0",
            "use multimon:i:0",
            "selectedmonitors:s:",
            "use redirection server name:i:0",
            "loadbalanceinfo:s:",
            "prevent server wallpaper:i:1",
            "prevent server desktop composition:i:0",
            "prevent server font smoothing:i:0",
            "prevent server cursor blinking:i:0",
            "prevent server cursor shadow:i:0",
            "prevent server drawing desktop wallpaper:i:0",
            "prevent server full window drag:i:0",
            "prevent server menu animations:i:0",
            "prevent server themes:i:0",
            "prevent server cursor setting:i:0",
            "bitmapcachepersistenable:i:1",
            "bitmapcachesize:i:1500",
            "audiomode:i:0",
            "redirectposdevices:i:0",
            "redirectdirectx:i:1",
            "autoreconnection enabled:i:1",
            "autoreconnection max retry count:i:20",
            "compression:i:1",
            "keyboardhook:i:2"
        ])
        
        return "\n".join(rdp_content)
    
    async def generate_connection_url(self, connection_id: str) -> str:
        """Generate a connection URL for the RDP connection."""
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found or expired")
        
        # Create connection URL
        params = {
            "id": connection_id,
            "host": connection.host,
            "port": connection.port,
            "username": connection.username
        }
        
        if connection.domain:
            params["domain"] = connection.domain
        
        if connection.gateway:
            params["gateway"] = connection.gateway
        
        # Add expiration timestamp
        params["expires"] = int(connection.expires_at)
        
        # Add signature for security
        signature = self._generate_signature(connection_id, params)
        params["sig"] = signature
        
        return f"{self.base_url}/connect?{urlencode(params)}"
    
    async def validate_connection_url(self, url: str) -> Optional[RDPConnection]:
        """Validate a connection URL and return the connection if valid."""
        try:
            from urllib.parse import urlparse, parse_qs
            
            parsed = urlparse(url)
            if parsed.path != "/connect":
                return None
            
            params = parse_qs(parsed.query)
            
            # Extract parameters
            connection_id = params.get("id", [None])[0]
            if not connection_id:
                return None
            
            # Get connection
            connection = await self.get_connection(connection_id)
            if not connection:
                return None
            
            # Validate signature
            expected_signature = self._generate_signature(connection_id, {
                "id": connection_id,
                "host": connection.host,
                "port": connection.port,
                "username": connection.username,
                "expires": int(connection.expires_at)
            })
            
            actual_signature = params.get("sig", [None])[0]
            if actual_signature != expected_signature:
                return None
            
            return connection
            
        except Exception:
            return None
    
    def _generate_connection_id(self) -> str:
        """Generate a unique connection ID."""
        timestamp = int(time.time())
        random_part = secrets.token_hex(8)
        return f"rdp_{timestamp}_{random_part}"
    
    def _generate_signature(self, connection_id: str, params: Dict[str, Any]) -> str:
        """Generate a signature for connection parameters."""
        # Create a deterministic string from parameters
        param_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        
        # Add a secret key (in production, this would be stored securely)
        secret_key = "rdp_broker_secret_key_change_in_production"
        
        # Generate signature
        signature_data = f"{connection_id}:{param_str}:{secret_key}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]
    
    async def _cleanup_expired_connections(self) -> None:
        """Background task to clean up expired connections."""
        while True:
            try:
                # Find expired connections
                expired_connections = [
                    conn_id for conn_id, connection in self._connections.items()
                    if connection.is_expired
                ]
                
                # Remove expired connections
                for conn_id in expired_connections:
                    del self._connections[conn_id]
                
                # Sleep for a bit before next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error and continue
                await asyncio.sleep(300)
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get RDP broker statistics."""
        now = time.time()
        active_connections = [c for c in self._connections.values() if not c.is_expired]
        expired_connections = [c for c in self._connections.values() if c.is_expired]
        
        return {
            "total_connections": len(self._connections),
            "active_connections": len(active_connections),
            "expired_connections": len(expired_connections),
            "profiles": {
                c.profile_id: len([c2 for c2 in active_connections if c2.profile_id == c.profile_id])
                for c in active_connections
            }
        }
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

"""VPN provider for OpenAccess MCP."""

import asyncio
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class VPNStatus:
    """VPN connection status."""
    
    interface: str
    status: str  # "up", "down", "connecting", "error"
    peer_id: Optional[str] = None
    config_id: Optional[str] = None
    ip_address: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class VPNProvider:
    """Handles VPN operations for WireGuard and OpenVPN."""
    
    def __init__(self):
        self._active_connections: Dict[str, VPNStatus] = {}
    
    async def wireguard_toggle(
        self,
        peer_id: str,
        action: str,
        config_path: Optional[str] = None,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Toggle WireGuard connection up/down."""
        if action not in ["up", "down"]:
            raise ValueError("Action must be 'up' or 'down'")
        
        try:
            if action == "up":
                return await self._wireguard_up(peer_id, config_path, interface_name)
            else:
                return await self._wireguard_down(peer_id, interface_name)
        except Exception as e:
            return VPNStatus(
                interface=interface_name or f"wg-{peer_id}",
                status="error",
                peer_id=peer_id,
                error=str(e)
            )
    
    async def _wireguard_up(
        self,
        peer_id: str,
        config_path: Optional[str] = None,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Bring WireGuard interface up."""
        interface = interface_name or f"wg-{peer_id}"
        
        # Check if interface already exists
        if await self._interface_exists(interface):
            return VPNStatus(
                interface=interface,
                status="up",
                peer_id=peer_id,
                error="Interface already exists"
            )
        
        # Use wg-quick to bring interface up
        if config_path:
            cmd = ["wg-quick", "up", config_path]
        else:
            # Create temporary config if none provided
            config_path = await self._create_temp_wg_config(peer_id)
            cmd = ["wg-quick", "up", config_path]
        
        try:
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                # Get interface status
                ip_info = await self._get_interface_ip(interface)
                
                status = VPNStatus(
                    interface=interface,
                    status="up",
                    peer_id=peer_id,
                    ip_address=ip_info.get("ip"),
                    metadata={"config_path": config_path}
                )
                
                self._active_connections[peer_id] = status
                return status
            else:
                return VPNStatus(
                    interface=interface,
                    status="error",
                    peer_id=peer_id,
                    error=f"wg-quick failed: {result.stderr}"
                )
                
        except Exception as e:
            return VPNStatus(
                interface=interface,
                status="error",
                peer_id=peer_id,
                error=str(e)
            )
    
    async def _wireguard_down(
        self,
        peer_id: str,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Bring WireGuard interface down."""
        interface = interface_name or f"wg-{peer_id}"
        
        if not await self._interface_exists(interface):
            return VPNStatus(
                interface=interface,
                status="down",
                peer_id=peer_id,
                error="Interface does not exist"
            )
        
        try:
            cmd = ["wg-quick", "down", interface]
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                status = VPNStatus(
                    interface=interface,
                    status="down",
                    peer_id=peer_id
                )
                
                # Remove from active connections
                self._active_connections.pop(peer_id, None)
                return status
            else:
                return VPNStatus(
                    interface=interface,
                    status="error",
                    peer_id=peer_id,
                    error=f"wg-quick down failed: {result.stderr}"
                )
                
        except Exception as e:
            return VPNStatus(
                interface=interface,
                status="error",
                peer_id=peer_id,
                error=str(e)
            )
    
    async def openvpn_toggle(
        self,
        config_id: str,
        action: str,
        config_path: str,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Toggle OpenVPN connection connect/disconnect."""
        if action not in ["connect", "disconnect"]:
            raise ValueError("Action must be 'connect' or 'disconnect'")
        
        try:
            if action == "connect":
                return await self._openvpn_connect(config_id, config_path, interface_name)
            else:
                return await self._openvpn_disconnect(config_id, interface_name)
        except Exception as e:
            return VPNStatus(
                interface=interface_name or f"tun-{config_id}",
                status="error",
                config_id=config_id,
                error=str(e)
            )
    
    async def _openvpn_connect(
        self,
        config_id: str,
        config_path: str,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Connect to OpenVPN."""
        interface = interface_name or f"tun-{config_id}"
        
        # Check if already connected
        if config_id in self._active_connections:
            return VPNStatus(
                interface=interface,
                status="up",
                config_id=config_id,
                error="Already connected"
            )
        
        try:
            # Start OpenVPN in background
            cmd = ["openvpn", "--config", config_path, "--daemon"]
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                # Wait a bit for connection to establish
                await asyncio.sleep(2)
                
                # Check connection status
                if await self._openvpn_connected(config_path):
                    status = VPNStatus(
                        interface=interface,
                        status="up",
                        config_id=config_id,
                        metadata={"config_path": config_path}
                    )
                    
                    self._active_connections[config_id] = status
                    return status
                else:
                    return VPNStatus(
                        interface=interface,
                        status="error",
                        config_id=config_id,
                        error="Connection failed to establish"
                    )
            else:
                return VPNStatus(
                    interface=interface,
                    status="error",
                    config_id=config_id,
                    error=f"OpenVPN failed: {result.stderr}"
                )
                
        except Exception as e:
            return VPNStatus(
                interface=interface,
                status="error",
                config_id=config_id,
                error=str(e)
            )
    
    async def _openvpn_disconnect(
        self,
        config_id: str,
        interface_name: Optional[str] = None
    ) -> VPNStatus:
        """Disconnect from OpenVPN."""
        interface = interface_name or f"tun-{config_id}"
        
        if config_id not in self._active_connections:
            return VPNStatus(
                interface=interface,
                status="down",
                config_id=config_id,
                error="Not connected"
            )
        
        try:
            # Kill OpenVPN processes for this config
            cmd = ["pkill", "-f", f"openvpn.*{config_id}"]
            await self._run_command(cmd)
            
            status = VPNStatus(
                interface=interface,
                status="down",
                config_id=config_id
            )
            
            # Remove from active connections
            self._active_connections.pop(config_id, None)
            return status
            
        except Exception as e:
            return VPNStatus(
                interface=interface,
                status="error",
                config_id=config_id,
                error=str(e)
            )
    
    async def list_connections(self) -> List[VPNStatus]:
        """List all active VPN connections."""
        return list(self._active_connections.values())
    
    async def get_connection_status(self, connection_id: str) -> Optional[VPNStatus]:
        """Get status of a specific connection."""
        return self._active_connections.get(connection_id)
    
    async def _interface_exists(self, interface: str) -> bool:
        """Check if network interface exists."""
        try:
            cmd = ["ip", "link", "show", interface]
            result = await self._run_command(cmd)
            return result.returncode == 0
        except Exception:
            return False
    
    async def _get_interface_ip(self, interface: str) -> Dict[str, str]:
        """Get IP address information for an interface."""
        try:
            cmd = ["ip", "addr", "show", interface]
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                # Parse IP address from output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line:
                        ip = line.split()[1].split('/')[0]
                        return {"ip": ip}
            
            return {}
        except Exception:
            return {}
    
    async def _openvpn_connected(self, config_path: str) -> bool:
        """Check if OpenVPN is connected for a specific config."""
        try:
            cmd = ["pgrep", "-f", f"openvpn.*{config_path}"]
            result = await self._run_command(cmd)
            return result.returncode == 0
        except Exception:
            return False
    
    async def _create_temp_wg_config(self, peer_id: str) -> str:
        """Create a temporary WireGuard configuration file."""
        # This is a placeholder - in production you'd load from a secure store
        config_content = f"""[Interface]
PrivateKey = <private_key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <public_key>
AllowedIPs = 10.0.0.2/32
"""
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        temp_file.write(config_content)
        temp_file.close()
        
        return temp_file.name
    
    async def _run_command(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run a command asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, subprocess.run, cmd, capture_output=True, text=True)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get VPN provider statistics."""
        return {
            "active_connections": len(self._active_connections),
            "connection_types": {
                "wireguard": len([c for c in self._active_connections.values() if c.peer_id]),
                "openvpn": len([c for c in self._active_connections.values() if c.config_id])
            }
        }
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        # This is a no-op for VPN provider as it doesn't have a cleanup task
        pass

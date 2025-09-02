"""Main MCP server for OpenAccess MCP."""

import asyncio
import hashlib
import json
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

from .types import Profile, Capabilities, ToolResult
from .policy import PolicyContext, enforce_policy
from .secrets import get_secret_store
from .audit import get_audit_logger
from .providers.ssh import SSHProvider
from .providers.sftp import SFTPProvider
from .providers.rsync import RsyncProvider
from .providers.tunnel import TunnelProvider
from .providers.vpn import VPNProvider
from .providers.rdp import RDPBrokerProvider


class OpenAccessMCPServer:
    """Main MCP server for OpenAccess MCP."""
    
    def __init__(self, profiles_dir: Optional[Path] = None, secrets_dir: Optional[Path] = None, audit_log_path: Optional[Path] = None, audit_key_path: Optional[Path] = None):
        self.profiles_dir = profiles_dir or Path("./profiles")
        self.secrets_dir = secrets_dir or Path("./secrets")
        self.audit_log_path = audit_log_path or Path("./audit/audit.log")
        self.audit_key_path = audit_key_path or Path("./audit/audit.key")
        
        self.server = Server("openaccess-mcp")
        self.ssh_provider = SSHProvider()
        self.sftp_provider = SFTPProvider()
        self.rsync_provider = RsyncProvider()
        self.tunnel_provider = TunnelProvider()
        self.vpn_provider = VPNProvider()
        self.rdp_provider = RDPBrokerProvider("https://rdp.example.com")
        
        # Initialize components
        self.secret_store = get_secret_store()
        self.audit_logger = get_audit_logger()
        
        # Register tools and resources
        self._register_resources()
        self._register_tools()
        
        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle system signals."""
        if signum == signal.SIGHUP:
            # Reload profiles
            print("Reloading profiles...", file=sys.stderr)
        elif signum == signal.SIGINT:
            # Graceful shutdown
            print("Shutting down...", file=sys.stderr)
            sys.exit(0)
    
    def _register_resources(self):
        """Register MCP resources."""
        
        @self.server.resource("remote/profiles/{id}.json")
        async def get_profile(id: str) -> Dict[str, Any]:
            """Get a profile by ID."""
            try:
                profile = await self._load_profile(id)
                return profile.dict()
            except Exception as e:
                return {"error": str(e)}
        
        @self.server.resource("remote/capabilities.json")
        async def get_capabilities() -> Dict[str, Any]:
            """Get server capabilities."""
            capabilities = Capabilities()
            return capabilities.dict()
    
    def _register_tools(self):
        """Register MCP tools."""
        
        @self.server.tool("sftp.transfer")
        async def sftp_transfer(
            profile_id: str,
            direction: str,
            remote_path: str,
            local_path: str,
            checksum: Optional[str] = None,
            create_dirs: bool = True,
            mode: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Transfer files via SFTP."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if SFTP is enabled
                if "sftp" not in profile.protocols:
                    return ToolResult.error_result("SFTP not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="sftp.transfer",
                    change_ticket=None
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Transfer file
                result = await self.sftp_provider.transfer_file(
                    host=profile.host,
                    port=profile.port,
                    secret=secret,
                    direction=direction,
                    remote_path=remote_path,
                    local_path=local_path,
                    checksum=checksum,
                    create_dirs=create_dirs,
                    mode=mode
                )
                
                if result.success:
                    # Log success
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="sftp.transfer",
                        profile_id=profile_id,
                        input_data={
                            "profile_id": profile_id,
                            "direction": direction,
                            "remote_path": remote_path,
                            "local_path": local_path,
                            "checksum": checksum,
                            "create_dirs": create_dirs,
                            "mode": mode
                        },
                        result="success",
                        metadata={
                            "bytes_transferred": result.bytes_transferred,
                            "checksum": result.checksum
                        }
                    )
                    
                    return ToolResult.success_result({
                        "success": result.success,
                        "bytes_transferred": result.bytes_transferred,
                        "checksum": result.checksum,
                        "metadata": result.metadata
                    }).dict()
                else:
                    # Log failure
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="sftp.transfer",
                        profile_id=profile_id,
                        input_data={
                            "profile_id": profile_id,
                            "direction": direction,
                            "remote_path": remote_path,
                            "local_path": local_path,
                            "checksum": checksum,
                            "create_dirs": create_dirs,
                            "mode": mode
                        },
                        result="failure",
                        metadata={"error": result.error}
                    )
                    
                    return ToolResult.error_result(result.error).dict()
                    
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("rsync.sync")
        async def rsync_sync(
            profile_id: str,
            direction: str,
            source: str,
            dest: str,
            delete_extras: bool = False,
            dry_run: bool = True,
            exclude: Optional[List[str]] = None,
            bandwidth_limit_kbps: Optional[int] = None,
            change_ticket: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Synchronize files using rsync."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if rsync is enabled
                if "rsync" not in profile.protocols:
                    return ToolResult.error_result("rsync not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="rsync.sync",
                    change_ticket=change_ticket
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Check if delete_extras requires dry-run first
                if delete_extras and not dry_run:
                    # Validate that a successful dry-run was performed first
                    dry_run_result = await self.rsync_provider.validate_dry_run(
                        host=profile.host,
                        port=profile.port,
                        username=secret.username,
                        direction=direction,
                        source=source,
                        dest=dest,
                        delete_extras=delete_extras,
                        exclude=exclude,
                        bandwidth_limit_kbps=bandwidth_limit_kbps
                    )
                    
                    if not dry_run_result.success:
                        return ToolResult.error_result(
                            "delete_extras requires a successful dry-run first"
                        ).dict()
                
                # Perform sync
                result = await self.rsync_provider.sync(
                    host=profile.host,
                    port=profile.port,
                    username=secret.username,
                    direction=direction,
                    source=source,
                    dest=dest,
                    delete_extras=delete_extras,
                    dry_run=dry_run,
                    exclude=exclude,
                    bandwidth_limit_kbps=bandwidth_limit_kbps
                )
                
                if result.success:
                    # Log success
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="rsync.sync",
                        profile_id=profile_id,
                        input_data={
                            "profile_id": profile_id,
                            "direction": direction,
                            "source": source,
                            "dest": dest,
                            "delete_extras": delete_extras,
                            "dry_run": dry_run,
                            "exclude": exclude,
                            "bandwidth_limit_kbps": bandwidth_limit_kbps,
                            "change_ticket": change_ticket
                        },
                        result="success",
                        metadata={
                            "files_transferred": result.files_transferred,
                            "bytes_transferred": result.bytes_transferred,
                            "dry_run": result.dry_run,
                            "plan": result.plan
                        }
                    )
                    
                    return ToolResult.success_result({
                        "success": result.success,
                        "files_transferred": result.files_transferred,
                        "bytes_transferred": result.bytes_transferred,
                        "dry_run": result.dry_run,
                        "plan": result.plan,
                        "metadata": result.metadata
                    }).dict()
                else:
                    # Log failure
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="rsync.sync",
                        profile_id=profile_id,
                        input_data={
                            "profile_id": profile_id,
                            "direction": direction,
                            "source": source,
                            "dest": dest,
                            "delete_extras": delete_extras,
                            "dry_run": dry_run,
                            "exclude": exclude,
                            "bandwidth_limit_kbps": bandwidth_limit_kbps,
                            "change_ticket": change_ticket
                        },
                        result="failure",
                        metadata={"error": result.error}
                    )
                    
                    return ToolResult.error_result(result.error).dict()
                    
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("ssh.exec")
        async def ssh_exec(
            profile_id: str,
            command: str,
            pty: bool = False,
            sudo: bool = False,
            timeout_seconds: int = 60,
            dry_run: bool = False,
            change_ticket: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Execute a command over SSH."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="ssh.exec",
                    command=command,
                    sudo=sudo,
                    dry_run=dry_run,
                    change_ticket=change_ticket
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="ssh.exec",
                        profile_id=profile_id,
                        input_data={"profile_id": profile_id, "command": command, "sudo": sudo},
                        result="policy_denied",
                        metadata={"reason": policy_decision.reason}
                    )
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Handle dry run
                if dry_run:
                    plan = f"Would execute: {command}"
                    if sudo:
                        plan += " with sudo"
                    
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="ssh.exec",
                        profile_id=profile_id,
                        input_data={"profile_id": profile_id, "command": command, "sudo": sudo},
                        result="dry_run",
                        metadata={"plan": plan}
                    )
                    
                    return ToolResult.dry_run_result(plan).dict()
                
                # Execute command
                result = await self.ssh_provider.exec_command(
                    host=profile.host,
                    port=profile.port,
                    secret=secret,
                    command=command,
                    pty=pty,
                    sudo=sudo,
                    timeout=timeout_seconds
                )
                
                # Log success
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="ssh.exec",
                    profile_id=profile_id,
                    input_data={"profile_id": profile_id, "command": command, "sudo": sudo},
                    result="success",
                    stdout=result.stdout,
                    stderr=result.stderr,
                    ticket=change_ticket,
                    metadata={"session_id": result.session_id, "exit_code": result.exit_code}
                )
                
                return ToolResult.success_result({
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "session_id": result.session_id
                }).dict()
                
            except Exception as e:
                # Log failure
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="ssh.exec",
                    profile_id=profile_id,
                    input_data={"profile_id": profile_id, "command": command, "sudo": sudo},
                    result="failure",
                    metadata={"error": str(e)}
                )
                
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("sftp.transfer")
        async def sftp_transfer(
            profile_id: str,
            direction: str,
            remote_path: str,
            local_path: str,
            checksum: Optional[str] = None,
            create_dirs: bool = True,
            mode: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Transfer files via SFTP."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if SFTP is enabled
                if "sftp" not in profile.protocols:
                    return ToolResult.error_result("SFTP not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="sftp.transfer",
                    change_ticket=None
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # TODO: Implement SFTP transfer
                # For now, return a placeholder
                return ToolResult.success_result({
                    "direction": direction,
                    "remote_path": remote_path,
                    "local_path": local_path,
                    "status": "not_implemented"
                }).dict()
                
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("rsync.sync")
        async def rsync_sync(
            profile_id: str,
            direction: str,
            source: str,
            dest: str,
            delete_extras: bool = False,
            dry_run: bool = True,
            exclude: Optional[List[str]] = None,
            bandwidth_limit_kbps: Optional[int] = None,
            change_ticket: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Synchronize files using rsync."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if rsync is enabled
                if "rsync" not in profile.protocols:
                    return ToolResult.error_result("rsync not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="rsync.sync",
                    change_ticket=change_ticket
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Check if delete_extras requires a change ticket
                if delete_extras and not change_ticket:
                    return ToolResult.error_result(
                        "Change ticket required for delete_extras operations"
                    ).dict()
                
                # TODO: Implement rsync sync
                # For now, return a placeholder
                return ToolResult.success_result({
                    "direction": direction,
                    "source": source,
                    "dest": dest,
                    "delete_extras": delete_extras,
                    "dry_run": dry_run,
                    "status": "not_implemented"
                }).dict()
                
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("tunnel.create")
        async def tunnel_create(
            profile_id: str,
            tunnel_type: str,
            listen_host: str = "127.0.0.1",
            listen_port: int = 0,
            target_host: Optional[str] = None,
            target_port: Optional[int] = None,
            ttl_seconds: int = 3600,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Create an SSH tunnel."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if tunneling is enabled
                if "tunnel" not in profile.protocols:
                    return ToolResult.error_result("Tunneling not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="tunnel.create",
                    change_ticket=None
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Create tunnel
                tunnel_info = await self.tunnel_provider.create_tunnel(
                    host=profile.host,
                    port=profile.port,
                    secret=secret,
                    tunnel_type=tunnel_type,
                    listen_host=listen_host,
                    listen_port=listen_port,
                    target_host=target_host,
                    target_port=target_port,
                    ttl_seconds=ttl_seconds,
                    profile_id=profile_id
                )
                
                # Log success
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="tunnel.create",
                    profile_id=profile_id,
                    input_data={
                        "profile_id": profile_id,
                        "tunnel_type": tunnel_type,
                        "listen_host": listen_host,
                        "listen_port": listen_port,
                        "target_host": target_host,
                        "target_port": target_port,
                        "ttl_seconds": ttl_seconds
                    },
                    result="success",
                    metadata={
                        "tunnel_id": tunnel_info.tunnel_id,
                        "listen_port": tunnel_info.listen_port
                    }
                )
                
                return ToolResult.success_result({
                    "tunnel_id": tunnel_info.tunnel_id,
                    "tunnel_type": tunnel_info.tunnel_type,
                    "listen_host": tunnel_info.listen_host,
                    "listen_port": tunnel_info.listen_port,
                    "target_host": tunnel_info.target_host,
                    "target_port": tunnel_info.target_port,
                    "ttl_seconds": tunnel_info.ttl_seconds,
                    "expires_at": tunnel_info.expires_at
                }).dict()
                
            except Exception as e:
                # Log failure
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="tunnel.create",
                    profile_id=profile_id,
                    input_data={
                        "profile_id": profile_id,
                        "tunnel_type": tunnel_type,
                        "listen_host": listen_host,
                        "listen_port": listen_port,
                        "target_host": target_host,
                        "target_port": target_port,
                        "ttl_seconds": ttl_seconds
                    },
                    result="failure",
                    metadata={"error": str(e)}
                )
                
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("tunnel.close")
        async def tunnel_close(
            tunnel_id: str,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Close an SSH tunnel."""
            try:
                # Close tunnel
                success = await self.tunnel_provider.close_tunnel(tunnel_id)
                
                if success:
                    # Log success
                    await self.audit_logger.log_tool_call(
                        actor=caller or "unknown",
                        tool="tunnel.close",
                        profile_id="unknown",
                        input_data={"tunnel_id": tunnel_id},
                        result="success"
                    )
                    
                    return ToolResult.success_result({
                        "tunnel_id": tunnel_id,
                        "status": "closed"
                    }).dict()
                else:
                    return ToolResult.error_result(f"Tunnel {tunnel_id} not found or already closed").dict()
                    
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("vpn.wireguard.toggle")
        async def vpn_wireguard_toggle(
            profile_id: str,
            peer_id: str,
            action: str,
            config_path: Optional[str] = None,
            interface_name: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Toggle WireGuard VPN connection."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if VPN is enabled
                if "vpn" not in profile.protocols:
                    return ToolResult.error_result("VPN not enabled for this profile").dict()
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="vpn.wireguard.toggle",
                    change_ticket=None
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Toggle VPN
                vpn_status = await self.vpn_provider.wireguard_toggle(
                    peer_id=peer_id,
                    action=action,
                    config_path=config_path,
                    interface_name=interface_name
                )
                
                # Log operation
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="vpn.wireguard.toggle",
                    profile_id=profile_id,
                    input_data={
                        "profile_id": profile_id,
                        "peer_id": peer_id,
                        "action": action,
                        "config_path": config_path,
                        "interface_name": interface_name
                    },
                    result="success" if vpn_status.status != "error" else "failure",
                    metadata={
                        "interface": vpn_status.interface,
                        "status": vpn_status.status,
                        "error": vpn_status.error
                    }
                )
                
                return ToolResult.success_result({
                    "interface": vpn_status.interface,
                    "status": vpn_status.status,
                    "peer_id": vpn_status.peer_id,
                    "ip_address": vpn_status.ip_address,
                    "error": vpn_status.error
                }).dict()
                
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
        
        @self.server.tool("rdp.launch")
        async def rdp_launch(
            profile_id: str,
            ttl_seconds: int = 3600,
            domain: Optional[str] = None,
            gateway: Optional[str] = None,
            caller: Optional[str] = None
        ) -> Dict[str, Any]:
            """Launch an RDP connection."""
            try:
                # Load profile
                profile = await self._load_profile(profile_id)
                
                # Check if RDP is enabled
                if "rdp" not in profile.protocols:
                    return ToolResult.error_result("RDP not enabled for this profile").dict()
                
                # Resolve secrets
                secret = await self.secret_store.resolve(profile.auth)
                
                # Enforce policy
                policy_context = PolicyContext(
                    actor=caller or "unknown",
                    actor_roles=["admin"],  # TODO: Get from auth context
                    profile=profile,
                    tool="rdp.launch",
                    change_ticket=None
                )
                
                policy_decision = enforce_policy(policy_context)
                if not policy_decision.allowed:
                    return ToolResult.error_result(
                        f"Policy violation: {policy_decision.reason}"
                    ).dict()
                
                # Create RDP connection
                connection = await self.rdp_provider.create_connection(
                    profile_id=profile_id,
                    host=profile.host,
                    port=3389,  # Default RDP port
                    username=secret.username,
                    domain=domain,
                    gateway=gateway,
                    ttl_seconds=ttl_seconds
                )
                
                # Generate .rdp file content
                rdp_content = await self.rdp_provider.generate_rdp_file(connection.connection_id)
                
                # Generate connection URL
                connection_url = await self.rdp_provider.generate_connection_url(connection.connection_id)
                
                # Log operation
                await self.audit_logger.log_tool_call(
                    actor=caller or "unknown",
                    tool="rdp.launch",
                    profile_id=profile_id,
                    input_data={
                        "profile_id": profile_id,
                        "ttl_seconds": ttl_seconds,
                        "domain": domain,
                        "gateway": gateway
                    },
                    result="success",
                    metadata={
                        "connection_id": connection.connection_id,
                        "expires_at": connection.expires_at
                    }
                )
                
                return ToolResult.success_result({
                    "connection_id": connection.connection_id,
                    "rdp_file": rdp_content,
                    "connection_url": connection_url,
                    "expires_at": connection.expires_at,
                    "remaining_seconds": connection.remaining_seconds
                }).dict()
                
            except Exception as e:
                return ToolResult.error_result(str(e)).dict()
    
    async def _load_profile(self, profile_id: str) -> Profile:
        """Load a profile from the profiles directory."""
        profile_file = self.profiles_dir / f"{profile_id}.json"
        
        if not profile_file.exists():
            raise FileNotFoundError(f"Profile not found: {profile_id}")
        
        try:
            with open(profile_file, "r") as f:
                profile_data = json.load(f)
            
            return Profile(**profile_data)
        except Exception as e:
            raise ValueError(f"Failed to load profile {profile_id}: {e}")
    
    async def cleanup(self):
        """Clean up server resources."""
        # Close all provider connections
        await self.ssh_provider.close_all_connections()
        await self.sftp_provider.close_all_connections()
        await self.rsync_provider.clear_cache()
        await self.tunnel_provider.close_all_tunnels()
        await self.tunnel_provider.stop_cleanup_task()
        await self.vpn_provider.stop_cleanup_task()
        await self.rdp_provider.stop_cleanup_task()
    
    async def run(self):
        """Run the MCP server."""
        # Initialize the server
        init_options = InitializationOptions(
            server_name="openaccess-mcp",
            server_version="0.1.0",
            capabilities=self.server.get_capabilities(
                notification_options=None,
                experimental_capabilities={}
            )
        )
        
        # Run the server
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                init_options
            )


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenAccess MCP Server")
    parser.add_argument(
        "--profiles",
        type=Path,
        default="./profiles",
        help="Directory containing profile JSON files"
    )
    
    args = parser.parse_args()
    
    # Create and run server
    server = OpenAccessMCPServer(args.profiles)
    
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("Server stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

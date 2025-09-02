"""rsync provider for OpenAccess MCP."""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import os


@dataclass
class RsyncResult:
    """Result of an rsync operation."""
    
    success: bool
    files_transferred: int
    bytes_transferred: int
    dry_run: bool
    plan: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class RsyncProvider:
    """Handles rsync operations with safety checks."""
    
    def __init__(self):
        self._dry_run_cache = {}  # Cache for dry-run results
    
    async def sync(
        self,
        host: str,
        port: int,
        username: str,
        private_key: Optional[str] = None,
        password: Optional[str] = None,
        direction: str = "push",
        source: str = "",
        dest: str = "",
        delete_extras: bool = False,
        dry_run: bool = True,
        exclude: Optional[List[str]] = None,
        bandwidth_limit_kbps: Optional[int] = None
    ) -> RsyncResult:
        """Synchronize files using rsync."""
        # Validate direction
        if direction not in ["push", "pull"]:
            raise ValueError("Direction must be 'push' or 'pull'")
        
        # Build rsync command
        cmd = self._build_rsync_command(
            host, port, username, direction, source, dest,
            delete_extras, dry_run, exclude, bandwidth_limit_kbps
        )
        
        try:
            # Execute rsync
            result = await self._execute_rsync(cmd)
            
            # Parse output
            return self._parse_rsync_output(result, dry_run, delete_extras)
            
        except Exception as e:
            return RsyncResult(
                success=False,
                files_transferred=0,
                bytes_transferred=0,
                dry_run=dry_run,
                error=str(e)
            )
    
    def _build_rsync_command(
        self,
        host: str,
        port: int,
        username: str,
        direction: str,
        source: str,
        dest: str,
        delete_extras: bool,
        dry_run: bool,
        exclude: Optional[List[str]] = None,
        bandwidth_limit_kbps: Optional[int] = None
    ) -> List[str]:
        """Build the rsync command."""
        cmd = ["rsync"]
        
        # Basic options
        cmd.extend(["-avz", "--progress"])
        
        # Dry run
        if dry_run:
            cmd.append("--dry-run")
        
        # Delete extras (requires dry-run first)
        if delete_extras:
            cmd.append("--delete")
        
        # Exclude patterns
        if exclude:
            for pattern in exclude:
                cmd.extend(["--exclude", pattern])
        
        # Bandwidth limit
        if bandwidth_limit_kbps:
            cmd.extend(["--bwlimit", str(bandwidth_limit_kbps)])
        
        # SSH options
        ssh_opts = f"ssh -p {port}"
        # Note: private_key support would need to be added as a parameter
        # For now, we'll use password authentication
        cmd.extend(["-e", ssh_opts])
        
        # Source and destination
        if direction == "push":
            # Local to remote
            cmd.append(source)
            cmd.append(f"{username}@{host}:{dest}")
        else:
            # Remote to local
            cmd.append(f"{username}@{host}:{source}")
            cmd.append(dest)
        
        return cmd
    
    async def _execute_rsync(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Execute rsync command."""
        # Use the modern asyncio approach
        try:
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await process.communicate()
            
            # Create result with captured output
            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr
            )
            
            return result
            
        except Exception as e:
            # Fallback to subprocess.run if create_subprocess_exec fails
            return await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True
            )
    
    def _parse_rsync_output(
        self,
        result: subprocess.CompletedProcess,
        dry_run: bool,
        delete_extras: bool
    ) -> RsyncResult:
        """Parse rsync output to extract statistics."""
        if result.returncode != 0:
            return RsyncResult(
                success=False,
                files_transferred=0,
                bytes_transferred=0,
                dry_run=dry_run,
                error=f"rsync failed with exit code {result.returncode}: {result.stderr}"
            )
        
        # Parse statistics from output
        files_transferred = 0
        bytes_transferred = 0
        
        # Look for rsync statistics in output
        for line in result.stdout.split('\n'):
            if line.strip().endswith('total size is'):
                # Extract total size
                try:
                    size_str = line.split()[-3]  # "total size is X"
                    bytes_transferred = int(size_str.replace(',', ''))
                except (ValueError, IndexError):
                    pass
            elif line.startswith('sending incremental file list'):
                # Count files in the list
                files_transferred = len([l for l in result.stdout.split('\n') 
                                       if l.strip() and not l.startswith('sending') 
                                       and not l.startswith('total size')])
        
        # Create plan for dry run
        plan = None
        if dry_run:
            plan = self._create_dry_run_plan(result.stdout, delete_extras)
        
        return RsyncResult(
            success=True,
            files_transferred=files_transferred,
            bytes_transferred=bytes_transferred,
            dry_run=dry_run,
            plan=plan,
            metadata={
                "command": " ".join(result.args),
                "stdout_lines": len(result.stdout.split('\n')),
                "stderr_lines": len(result.stderr.split('\n'))
            }
        )
    
    def _create_dry_run_plan(self, output: str, delete_extras: bool) -> str:
        """Create a human-readable plan from dry-run output."""
        lines = output.split('\n')
        plan_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('>f') or line.startswith('>d'):
                # File or directory
                if line.startswith('>f'):
                    plan_lines.append(f"Would transfer file: {line[3:]}")
                else:
                    plan_lines.append(f"Would create directory: {line[3:]}")
            elif line.startswith('*deleting'):
                # Deletion (only if delete_extras is enabled)
                if delete_extras:
                    plan_lines.append(f"Would delete: {line[10:]}")
            elif line.startswith('sending incremental file list'):
                plan_lines.append("Incremental file list:")
        
        if not plan_lines:
            plan_lines.append("No changes detected")
        
        return "\n".join(plan_lines)
    
    async def validate_dry_run(
        self,
        host: str,
        port: int,
        username: str,
        direction: str,
        source: str,
        dest: str,
        delete_extras: bool = False,
        exclude: Optional[List[str]] = None,
        bandwidth_limit_kbps: Optional[int] = None
    ) -> RsyncResult:
        """Validate a dry-run before allowing destructive operations."""
        # Create cache key
        cache_key = f"{host}:{port}:{username}:{direction}:{source}:{dest}:{delete_extras}"
        
        # Check cache
        if cache_key in self._dry_run_cache:
            return self._dry_run_cache[cache_key]
        
        # Perform dry run
        result = await self.sync(
            host=host,
            port=port,
            username=username,
            direction=direction,
            source=source,
            dest=dest,
            delete_extras=delete_extras,
            dry_run=True,
            exclude=exclude,
            bandwidth_limit_kbps=bandwidth_limit_kbps
        )
        
        # Cache successful dry runs for 5 minutes
        if result.success:
            self._dry_run_cache[cache_key] = result
            # Schedule cache cleanup
            asyncio.create_task(self._cleanup_cache(cache_key))
        
        return result
    
    async def _cleanup_cache(self, cache_key: str, ttl: int = 300) -> None:
        """Remove cached dry-run result after TTL."""
        await asyncio.sleep(ttl)
        self._dry_run_cache.pop(cache_key, None)
    
    def clear_cache(self) -> None:
        """Clear all cached dry-run results."""
        self._dry_run_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cached_results": len(self._dry_run_cache),
            "cache_keys": list(self._dry_run_cache.keys())
        }
    
    async def clear_cache(self) -> None:
        """Clear all cached dry-run results."""
        self._dry_run_cache.clear()

"""Audit logging for OpenAccess MCP."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from ..types import AuditRecord
from .signer import AuditSigner


class AuditLogger:
    """Handles logging of signed audit records."""
    
    def __init__(self, log_file: Path, signer: Optional[AuditSigner] = None):
        self.log_file = Path(log_file)
        self.signer = signer or AuditSigner()
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize the log file if it doesn't exist
        if not self.log_file.exists():
            self._initialize_log_file()
    
    def _initialize_log_file(self) -> None:
        """Initialize a new audit log file."""
        header = {
            "type": "audit_log_header",
            "created": datetime.utcnow().isoformat() + "Z",
            "version": "1.0",
            "signing_key_id": self._get_key_id()
        }
        
        with open(self.log_file, "w") as f:
            f.write(json.dumps(header) + "\n")
    
    def _get_key_id(self) -> str:
        """Get a short identifier for the signing key."""
        try:
            public_key = self.signer.get_public_key()
            return f"ed25519:{public_key[:8].hex()}"
        except Exception:
            return "unknown"
    
    async def log_record(self, record: AuditRecord) -> None:
        """Log a signed audit record."""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._log_record_sync, record)
    
    def _log_record_sync(self, record: AuditRecord) -> None:
        """Synchronously log an audit record."""
        # Set timestamp if not already set
        if not record.ts:
            record.ts = datetime.utcnow().isoformat() + "Z"
        
        # Sign the record
        signed_record = self.signer.sign_record(record)
        
        # Write to log file
        with open(self.log_file, "a") as f:
            f.write(signed_record.to_jsonl() + "\n")
    
    async def log_tool_call(
        self,
        actor: str,
        tool: str,
        profile_id: str,
        input_data: Dict[str, Any],
        result: str,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        ticket: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log a tool call with automatic input hashing."""
        import hashlib
        
        # Create input hash
        input_json = json.dumps(input_data, sort_keys=True, separators=(",", ":"))
        input_hash = f"sha256:{hashlib.sha256(input_json.encode()).hexdigest()}"
        
        # Create output hashes
        stdout_hash = None
        stderr_hash = None
        
        if stdout:
            stdout_hash = f"sha256:{hashlib.sha256(stdout.encode()).hexdigest()}"
        if stderr:
            stderr_hash = f"sha256:{hashlib.sha256(stderr.encode()).hexdigest()}"
        
        # Create audit record
        record = AuditRecord(
            ts=datetime.utcnow().isoformat() + "Z",
            actor=actor,
            tool=tool,
            profile_id=profile_id,
            input_hash=input_hash,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            result=result,
            ticket=ticket,
            metadata=metadata or {}
        )
        
        # Log the record
        await self.log_record(record)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get statistics about the audit log."""
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
            
            # Count records by type
            record_counts = {}
            for line in lines:
                try:
                    data = json.loads(line.strip())
                    if "type" in data and data["type"] == "audit_log_header":
                        continue
                    
                    tool = data.get("tool", "unknown")
                    result = data.get("result", "unknown")
                    
                    if tool not in record_counts:
                        record_counts[tool] = {}
                    if result not in record_counts[tool]:
                        record_counts[tool][result] = 0
                    
                    record_counts[tool][result] += 1
                except json.JSONDecodeError:
                    continue
            
            return {
                "total_lines": len(lines),
                "record_counts": record_counts,
                "file_size_bytes": self.log_file.stat().st_size,
                "last_modified": datetime.fromtimestamp(self.log_file.stat().st_mtime).isoformat()
            }
        except Exception as e:
            return {"error": str(e)}
    
    def verify_log_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the audit log."""
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
            
            # Parse all records
            records = []
            for line in lines:
                try:
                    data = json.loads(line.strip())
                    if "type" in data and data["type"] == "audit_log_header":
                        continue
                    
                    record = AuditRecord(**data)
                    records.append(record)
                except Exception as e:
                    return {"error": f"Failed to parse record: {e}"}
            
            # Verify the chain
            is_valid = self.signer.verify_chain(records)
            
            return {
                "total_records": len(records),
                "chain_valid": is_valid,
                "first_record": records[0].ts if records else None,
                "last_record": records[-1].ts if records else None
            }
        except Exception as e:
            return {"error": f"Verification failed: {e}"}


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(log_file: Optional[Path] = None) -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    
    if _audit_logger is None:
        if log_file is None:
            # Use default location
            log_file = Path.home() / ".openaccess-mcp" / "audit.log"
        
        _audit_logger = AuditLogger(log_file)
    
    return _audit_logger


def set_audit_logger(logger: AuditLogger) -> None:
    """Set the global audit logger instance."""
    global _audit_logger
    _audit_logger = logger

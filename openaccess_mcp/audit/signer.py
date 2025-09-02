"""Audit signing and verification for OpenAccess MCP."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from ..types import AuditRecord


class AuditSigner:
    """Handles Ed25519 signing and hash chaining for audit records."""
    
    def __init__(self, private_key_path: Optional[Path] = None):
        self.private_key_path = private_key_path
        self._signing_key = None
        self._last_hash: Optional[str] = None
        
        if private_key_path:
            self._load_signing_key()
    
    def _load_signing_key(self) -> None:
        """Load the Ed25519 signing key."""
        try:
            from nacl.signing import SigningKey
        except ImportError:
            raise ImportError("PyNaCl is required for audit signing")
        
        if self.private_key_path and self.private_key_path.exists():
            with open(self.private_key_path, "rb") as f:
                key_data = f.read()
                self._signing_key = SigningKey(key_data)
        else:
            # Generate a new key if none exists
            self._signing_key = SigningKey.generate()
            
            # Save the key
            if self.private_key_path:
                self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.private_key_path, "wb") as f:
                    f.write(bytes(self._signing_key))
                
                # Set restrictive permissions
                self.private_key_path.chmod(0o600)
    
    def get_public_key(self) -> bytes:
        """Get the public key for verification."""
        if not self._signing_key:
            raise RuntimeError("Signing key not loaded")
        return bytes(self._signing_key.verify_key)
    
    def sign_record(self, record: AuditRecord) -> AuditRecord:
        """Sign an audit record and chain it to the previous record."""
        if not self._signing_key:
            raise RuntimeError("Signing key not loaded")
        
        # Set the chain reference to the previous record
        if self._last_hash:
            record.chain_prev = self._last_hash
        
        # Compute the hash of this record
        record_hash = record.compute_hash()
        
        # Create the data to sign (record hash + previous hash)
        data_to_sign = f"{record_hash}:{record.chain_prev or ''}"
        
        # Sign the data
        signature = self._signing_key.sign(data_to_sign.encode())
        
        # Store the signature
        record.chain_sig = f"ed25519:{signature.signature.hex()}"
        
        # Update the last hash for chaining
        self._last_hash = record_hash
        
        return record
    
    def verify_chain(self, records: list[AuditRecord]) -> bool:
        """Verify the integrity of a chain of audit records."""
        if not records:
            return True
        
        try:
            from nacl.signing import VerifyKey
        except ImportError:
            raise ImportError("PyNaCl is required for audit verification")
        
        # Get the public key from the first record's signature
        if not records[0].chain_sig:
            return False
        
        # Extract public key from first signature
        first_sig = records[0].chain_sig
        if not first_sig.startswith("ed25519:"):
            return False
        
        # For now, we'll assume the public key is available
        # In a real implementation, you'd need to store/retrieve the public key
        verify_key = VerifyKey(self.get_public_key())
        
        prev_hash = None
        
        for i, record in enumerate(records):
            # Verify the record hash
            expected_hash = record.compute_hash()
            
            # Check chain reference
            if i > 0 and record.chain_prev != prev_hash:
                return False
            
            # Verify signature if present
            if record.chain_sig and record.chain_sig.startswith("ed25519:"):
                sig_hex = record.chain_sig[8:]  # Remove "ed25519:" prefix
                signature = bytes.fromhex(sig_hex)
                
                # Create the data that was signed
                data_signed = f"{expected_hash}:{record.chain_prev or ''}"
                
                try:
                    verify_key.verify(data_signed.encode(), signature)
                except Exception:
                    return False
            
            prev_hash = expected_hash
        
        return True
    
    def generate_keypair(self, output_dir: Path) -> tuple[Path, Path]:
        """Generate a new Ed25519 keypair."""
        try:
            from nacl.signing import SigningKey
        except ImportError:
            raise ImportError("PyNaCl is required for key generation")
        
        # Generate new key
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save private key
        private_key_path = output_dir / "audit_private.key"
        with open(private_key_path, "wb") as f:
            f.write(bytes(signing_key))
        private_key_path.chmod(0o600)
        
        # Save public key
        public_key_path = output_dir / "audit_public.key"
        with open(public_key_path, "wb") as f:
            f.write(bytes(verify_key))
        public_key_path.chmod(0o644)
        
        return private_key_path, public_key_path


def create_audit_signer(key_path: Optional[Path] = None) -> AuditSigner:
    """Create an audit signer instance."""
    if key_path is None:
        # Use default location
        key_path = Path.home() / ".openaccess-mcp" / "audit_private.key"
    
    return AuditSigner(key_path)

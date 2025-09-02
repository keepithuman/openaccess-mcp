"""Secret providers for OpenAccess MCP."""

import json
import asyncio
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any

from ..types import SecretData


class SecretProvider(ABC):
    """Abstract base class for secret providers."""
    
    @abstractmethod
    async def resolve(self, ref: str) -> SecretData:
        """Resolve a secret reference to actual credentials."""
        pass


class VaultProvider(SecretProvider):
    """HashiCorp Vault secret provider."""
    
    def __init__(self, vault_addr: str, vault_token: str):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self._client = None
    
    async def resolve(self, ref: str) -> SecretData:
        """Resolve a Vault reference to credentials."""
        # Lazy import to avoid dependency issues
        try:
            import hvac
        except ImportError:
            raise ImportError("hvac is required for Vault integration")
        
        if not self._client:
            self._client = hvac.Client(
                url=self.vault_addr,
                token=self.vault_token
            )
        
        # Parse the reference (e.g., "kv/ssh/prod-web-01")
        parts = ref.split("/")
        if len(parts) < 3:
            raise ValueError(f"Invalid Vault reference format: {ref}")
        
        mount_point = parts[0]
        secret_path = "/".join(parts[1:])
        
        try:
            if mount_point == "kv":
                # KV v2
                response = self._client.secrets.kv.v2.read_secret(
                    path=secret_path,
                    mount_point="secret"
                )
                secret_data = response["data"]["data"]
            else:
                # Generic secret
                response = self._client.secrets.kv.v1.read_secret(
                    path=secret_path,
                    mount_point=mount_point
                )
                secret_data = response["data"]
            
            return SecretData(
                username=secret_data.get("username"),
                private_key=secret_data.get("private_key"),
                password=secret_data.get("password"),
                passphrase=secret_data.get("passphrase")
            )
            
        except Exception as e:
            raise ValueError(f"Failed to resolve Vault secret {ref}: {e}")


class FileProvider(SecretProvider):
    """File-based secret provider for development/testing."""
    
    def __init__(self, secrets_dir: Path):
        self.secrets_dir = Path(secrets_dir)
        if not self.secrets_dir.exists():
            self.secrets_dir.mkdir(parents=True, exist_ok=True)
    
    async def resolve(self, ref: str) -> SecretData:
        """Resolve a file reference to credentials."""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._resolve_sync, ref)
    
    def _resolve_sync(self, ref: str) -> SecretData:
        """Synchronous file resolution."""
        secret_file = self.secrets_dir / f"{ref}.json"
        
        if not secret_file.exists():
            raise ValueError(f"Secret file not found: {secret_file}")
        
        try:
            with open(secret_file, "r") as f:
                secret_data = json.load(f)
            
            return SecretData(
                username=secret_data.get("username"),
                private_key=secret_data.get("private_key"),
                password=secret_data.get("password"),
                passphrase=secret_data.get("passphrase")
            )
            
        except Exception as e:
            raise ValueError(f"Failed to read secret file {secret_file}: {e}")
    
    def create_secret(self, ref: str, secret_data: Dict[str, Any]) -> None:
        """Create a new secret file (for development/testing)."""
        secret_file = self.secrets_dir / f"{ref}.json"
        
        # Ensure the file has proper permissions
        with open(secret_file, "w") as f:
            json.dump(secret_data, f, indent=2)
        
        # Set restrictive permissions (owner read/write only)
        secret_file.chmod(0o600)


class KeychainProvider(SecretProvider):
    """OS keychain secret provider."""
    
    def __init__(self):
        try:
            import keyring
            self.keyring = keyring
        except ImportError:
            raise ImportError("keyring is required for keychain integration")
    
    async def resolve(self, ref: str) -> SecretData:
        """Resolve a keychain reference to credentials."""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._resolve_sync, ref)
    
    def _resolve_sync(self, ref: str) -> SecretData:
        """Synchronous keychain resolution."""
        # Parse reference format: "service:username"
        if ":" not in ref:
            raise ValueError(f"Invalid keychain reference format: {ref}")
        
        service, username = ref.split(":", 1)
        
        try:
            # Get password from keychain
            password = self.keyring.get_password(service, username)
            if not password:
                raise ValueError(f"No password found for {service}:{username}")
            
            # For SSH keys, we might store the key path in the password field
            # and the actual key content separately
            if service.startswith("ssh_"):
                # Try to get private key content
                private_key = self.keyring.get_password(f"{service}_key", username)
                return SecretData(
                    username=username,
                    private_key=private_key,
                    password=None,
                    passphrase=password  # Use password field for passphrase
                )
            else:
                return SecretData(
                    username=username,
                    private_key=None,
                    password=password,
                    passphrase=None
                )
                
        except Exception as e:
            raise ValueError(f"Failed to resolve keychain secret {ref}: {e}")
    
    def store_secret(self, service: str, username: str, password: str) -> None:
        """Store a secret in the keychain."""
        self.keyring.set_password(service, username, password)
    
    def store_ssh_key(self, username: str, private_key: str, passphrase: str) -> None:
        """Store SSH key credentials in the keychain."""
        # Store passphrase
        self.keyring.set_password("ssh_passphrase", username, passphrase)
        # Store private key content
        self.keyring.set_password("ssh_key", username, private_key)

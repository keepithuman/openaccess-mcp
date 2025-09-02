"""Secret store for OpenAccess MCP."""

import asyncio
from typing import Dict, Optional
from pathlib import Path

from ..types import AuthRef, SecretData
from .providers import VaultProvider, FileProvider, KeychainProvider


class SecretStore:
    """Centralized secret store that coordinates different providers."""
    
    def __init__(self):
        self._providers: Dict[str, any] = {}
        self._cache: Dict[str, SecretData] = {}
        self._cache_ttl = 300  # 5 minutes
    
    def register_provider(self, provider_type: str, provider: any) -> None:
        """Register a secret provider."""
        self._providers[provider_type] = provider
    
    async def resolve(self, auth_ref: AuthRef) -> SecretData:
        """Resolve a secret reference to actual credentials."""
        cache_key = f"{auth_ref.type}:{auth_ref.ref}"
        
        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Get the appropriate provider
        provider = self._providers.get(auth_ref.type)
        if not provider:
            raise ValueError(f"No provider registered for type: {auth_ref.type}")
        
        # Resolve the secret
        secret_data = await provider.resolve(auth_ref.ref)
        
        # Cache the result
        self._cache[cache_key] = secret_data
        
        # Schedule cache cleanup
        asyncio.create_task(self._cleanup_cache(cache_key))
        
        return secret_data
    
    async def _cleanup_cache(self, cache_key: str) -> None:
        """Remove cached secret after TTL."""
        await asyncio.sleep(self._cache_ttl)
        self._cache.pop(cache_key, None)
    
    def clear_cache(self) -> None:
        """Clear all cached secrets."""
        self._cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_secrets": len(self._cache),
            "providers": len(self._providers)
        }


# Global secret store instance
_secret_store = SecretStore()


def get_secret_store() -> SecretStore:
    """Get the global secret store instance."""
    return _secret_store


def initialize_secret_store(
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    secrets_dir: Optional[Path] = None,
    enable_keychain: bool = True
) -> SecretStore:
    """Initialize the global secret store with providers."""
    store = get_secret_store()
    
    # Register Vault provider if configured
    if vault_addr and vault_token:
        vault_provider = VaultProvider(vault_addr, vault_token)
        store.register_provider("vault_ref", vault_provider)
    
    # Register file provider
    if secrets_dir:
        file_provider = FileProvider(secrets_dir)
        store.register_provider("file_ref", file_provider)
    
    # Register keychain provider
    if enable_keychain:
        try:
            keychain_provider = KeychainProvider()
            store.register_provider("keychain_ref", keychain_provider)
        except ImportError:
            # Keychain not available on this platform
            pass
    
    return store

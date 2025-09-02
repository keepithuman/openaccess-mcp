"""Authentication context for OpenAccess MCP."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from pathlib import Path
import json
import jwt
from pydantic import BaseModel, Field


class User(BaseModel):
    """User model for authentication."""
    
    id: str
    username: str
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None


class AuthContext(BaseModel):
    """Authentication context for tool execution."""
    
    user_id: str
    username: str
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def is_authenticated(self) -> bool:
        """Check if the user is authenticated."""
        return bool(self.user_id and self.roles)
    
    def has_role(self, role: str) -> bool:
        """Check if the user has a specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        return permission in self.permissions


class AuthProvider:
    """Base authentication provider."""
    
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthContext]:
        """Authenticate user with credentials."""
        raise NotImplementedError
    
    async def validate_token(self, token: str) -> Optional[AuthContext]:
        """Validate authentication token."""
        raise NotImplementedError
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles."""
        raise NotImplementedError


class FileBasedAuthProvider(AuthProvider):
    """File-based authentication provider."""
    
    def __init__(self, users_file: Optional[Path] = None):
        self.users_file = users_file or Path("./config/users.json")
        self.users: Dict[str, User] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.secret_key = "your-secret-key-here"  # In production, use environment variable
        
        # Load users
        self._load_users()
    
    def _load_users(self):
        """Load users from file."""
        try:
            if self.users_file.exists():
                with open(self.users_file, 'r') as f:
                    users_data = json.load(f)
                    for user_data in users_data:
                        user = User(**user_data)
                        self.users[user.id] = user
        except Exception as e:
            print(f"Warning: Could not load users file: {e}")
            # Create default admin user
            self.users["admin"] = User(
                id="admin",
                username="admin",
                roles=["admin"],
                permissions=["*"]
            )
    
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthContext]:
        """Authenticate user with username/password."""
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            return None
        
        # Find user by username
        user = None
        for u in self.users.values():
            if u.username == username:
                user = u
                break
        
        if not user or not user.is_active:
            return None
        
        # Simple password check (in production, use proper hashing)
        if password == "admin":  # Default password for demo
            # Update last login
            user.last_login = datetime.utcnow()
            
            # Create auth context
            context = AuthContext(
                user_id=user.id,
                username=user.username,
                roles=user.roles,
                permissions=user.permissions,
                session_id=f"session_{user.id}_{datetime.utcnow().timestamp()}",
                token_expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            
            return context
        
        return None
    
    async def validate_token(self, token: str) -> Optional[AuthContext]:
        """Validate JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            user_id = payload.get("user_id")
            
            if not user_id or user_id not in self.users:
                return None
            
            user = self.users[user_id]
            if not user.is_active:
                return None
            
            # Check if token is expired
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                return None
            
            return AuthContext(
                user_id=user.id,
                username=user.username,
                roles=user.roles,
                permissions=user.permissions,
                session_id=payload.get("session_id"),
                token_expires_at=datetime.fromtimestamp(exp) if exp else None
            )
            
        except jwt.InvalidTokenError:
            return None
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles."""
        user = self.users.get(user_id)
        return user.roles if user else []
    
    def create_token(self, context: AuthContext) -> str:
        """Create JWT token for user."""
        payload = {
            "user_id": context.user_id,
            "username": context.username,
            "roles": context.roles,
            "session_id": context.session_id,
            "exp": context.token_expires_at.timestamp() if context.token_expires_at else None
        }
        
        return jwt.encode(payload, self.secret_key, algorithm="HS256")


class NoAuthProvider(AuthProvider):
    """No authentication provider for development/testing."""
    
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthContext]:
        """Always return admin context."""
        return AuthContext(
            user_id="anonymous",
            username="anonymous",
            roles=["admin"],
            permissions=["*"]
        )
    
    async def validate_token(self, token: str) -> Optional[AuthContext]:
        """Always return admin context."""
        return AuthContext(
            user_id="anonymous",
            username="anonymous",
            roles=["admin"],
            permissions=["*"]
        )
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Always return admin role."""
        return ["admin"]


def get_auth_provider(provider_type: str = "file", **kwargs) -> AuthProvider:
    """Get authentication provider by type."""
    if provider_type == "file":
        return FileBasedAuthProvider(**kwargs)
    elif provider_type == "none":
        return NoAuthProvider()
    else:
        raise ValueError(f"Unknown auth provider type: {provider_type}")


# Global auth provider instance
_auth_provider: Optional[AuthProvider] = None


def get_auth_provider_instance() -> AuthProvider:
    """Get the global auth provider instance."""
    global _auth_provider
    if _auth_provider is None:
        _auth_provider = get_auth_provider("none")  # Default to no auth for development
    return _auth_provider


def set_auth_provider(provider: AuthProvider):
    """Set the global auth provider instance."""
    global _auth_provider
    _auth_provider = provider

"""OpenAccess MCP - A secure, policy-driven MCP server for remote access."""

__version__ = "0.1.0"
__author__ = "OpenAccess MCP Contributors"
__email__ = "team@openaccess-mcp.dev"

from .server import OpenAccessMCPServer
from .types import Profile, Capabilities, AuditRecord, Policy, AuthRef

__all__ = [
    "OpenAccessMCPServer",
    "Profile",
    "Capabilities", 
    "AuditRecord",
    "Policy",
    "AuthRef",
]

"""Policy-related exceptions for OpenAccess MCP."""


class PolicyError(Exception):
    """Base class for policy-related errors."""
    pass


class PolicyViolationError(PolicyError):
    """Raised when a policy violation is detected."""
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.details = details or {}


class PolicyConfigurationError(PolicyError):
    """Raised when there's an error in policy configuration."""
    pass


class PolicyEvaluationError(PolicyError):
    """Raised when there's an error evaluating a policy."""
    pass


class ChangeTicketRequiredError(PolicyError):
    """Raised when a change ticket is required but not provided."""
    
    def __init__(self, operation: str, ticket_type: str = "change"):
        message = f"Change ticket required for operation: {operation}"
        super().__init__(message)
        self.operation = operation
        self.ticket_type = ticket_type


class RoleAccessDeniedError(PolicyError):
    """Raised when access is denied due to insufficient roles."""
    
    def __init__(self, required_roles: list, user_roles: list):
        message = f"Access denied. Required roles: {required_roles}, User roles: {user_roles}"
        super().__init__(message)
        self.required_roles = required_roles
        self.user_roles = user_roles


class CommandNotAllowedError(PolicyError):
    """Raised when a command is not allowed by policy."""
    
    def __init__(self, command: str, reason: str = "Command not in allowlist"):
        message = f"Command not allowed: {command}. Reason: {reason}"
        super().__init__(message)
        self.command = command
        self.reason = reason


class SudoDeniedError(PolicyError):
    """Raised when sudo is denied by policy."""
    
    def __init__(self, command: str):
        message = f"Sudo denied for command: {command}"
        super().__init__(message)
        self.command = command


class SessionLimitExceededError(PolicyError):
    """Raised when session limits are exceeded."""
    
    def __init__(self, limit_type: str, current: int, maximum: int):
        message = f"Session limit exceeded: {limit_type} ({current}/{maximum})"
        super().__init__(message)
        self.limit_type = limit_type
        self.current = current
        self.maximum = maximum

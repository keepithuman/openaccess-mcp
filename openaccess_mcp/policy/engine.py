"""Policy enforcement engine for OpenAccess MCP."""

import re
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager

from ..types import Profile, Policy, PolicyDecision
from .exceptions import (
    PolicyViolationError,
    ChangeTicketRequiredError,
    RoleAccessDeniedError,
    CommandNotAllowedError,
    SudoDeniedError,
    SessionLimitExceededError,
)


@dataclass
class PolicyContext:
    """Context for policy evaluation."""
    
    actor: str
    actor_roles: List[str]
    profile: Profile
    tool: str
    command: Optional[str] = None
    sudo: bool = False
    dry_run: bool = False
    change_ticket: Optional[str] = None
    timestamp: Optional[float] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class PolicyEngine:
    """Policy enforcement engine."""
    
    def __init__(self):
        self._active_sessions: Dict[str, Dict[str, int]] = {}  # actor -> profile -> count
        self._session_start_times: Dict[str, Dict[str, float]] = {}  # actor -> profile -> start_time
    
    def enforce_policy(self, context: PolicyContext) -> PolicyDecision:
        """Enforce all applicable policies and return decision."""
        try:
            # Check role-based access
            self._check_role_access(context)
            
            # Check command allowlist/denylist
            if context.command:
                self._check_command_policy(context)
            
            # Check sudo permissions
            if context.sudo:
                self._check_sudo_policy(context)
            
            # Check change ticket requirements
            self._check_change_ticket_requirements(context)
            
            # Check session limits
            self._check_session_limits(context)
            
            # All checks passed
            return PolicyDecision.allow(
                restrictions=self._get_applied_restrictions(context)
            )
            
        except PolicyViolationError as e:
            return PolicyDecision.deny(
                reason=str(e),
                restrictions=self._get_applied_restrictions(context)
            )
    
    def _check_role_access(self, context: PolicyContext) -> None:
        """Check if actor has required roles for the profile."""
        profile_roles = set(context.profile.policy.roles)
        actor_roles = set(context.actor_roles)
        
        if not profile_roles:
            # No roles required, allow access
            return
        
        if not actor_roles.intersection(profile_roles):
            raise RoleAccessDeniedError(
                required_roles=list(profile_roles),
                user_roles=list(actor_roles)
            )
    
    def _check_command_policy(self, context: PolicyContext) -> None:
        """Check if command is allowed by policy."""
        if not context.command:
            return
        
        command = context.command.strip()
        policy = context.profile.policy
        
        # Check denylist first (takes precedence)
        for pattern in policy.command_denylist:
            if re.match(pattern, command, re.IGNORECASE):
                raise CommandNotAllowedError(
                    command=command,
                    reason=f"Command matches denylist pattern: {pattern}"
                )
        
        # Check allowlist
        if policy.command_allowlist:
            allowed = False
            for pattern in policy.command_allowlist:
                if re.match(pattern, command, re.IGNORECASE):
                    allowed = True
                    break
            
            if not allowed:
                raise CommandNotAllowedError(
                    command=command,
                    reason="Command not in allowlist"
                )
    
    def _check_sudo_policy(self, context: PolicyContext) -> None:
        """Check if sudo is allowed by policy."""
        if context.profile.policy.deny_sudo:
            raise SudoDeniedError(context.command or "unknown")
    
    def _check_change_ticket_requirements(self, context: PolicyContext) -> None:
        """Check if change ticket is required for the operation."""
        policy = context.profile.policy
        required_operations = policy.require_change_ticket_for
        
        # Determine operation type
        operation = self._get_operation_type(context)
        
        if operation in required_operations and not context.change_ticket:
            raise ChangeTicketRequiredError(operation)
    
    def _check_session_limits(self, context: PolicyContext) -> None:
        """Check session limits for the actor/profile combination."""
        policy = context.profile.policy
        actor = context.actor
        profile_id = context.profile.id
        
        # Check concurrent sessions
        current_sessions = self._active_sessions.get(actor, {}).get(profile_id, 0)
        if current_sessions >= policy.max_concurrent_sessions:
            raise SessionLimitExceededError(
                "concurrent_sessions",
                current_sessions,
                policy.max_concurrent_sessions
            )
        
        # Check session duration
        if profile_id in self._session_start_times.get(actor, {}):
            start_time = self._session_start_times[actor][profile_id]
            duration = context.timestamp - start_time
            if duration > policy.max_session_seconds:
                raise SessionLimitExceededError(
                    "session_duration",
                    int(duration),
                    policy.max_session_seconds
                )
    
    def _get_operation_type(self, context: PolicyContext) -> str:
        """Determine the operation type for change ticket checking."""
        if context.tool == "rsync.sync":
            if context.command and "delete" in context.command:
                return "rsync.delete"
            return "rsync.sync"
        elif context.tool == "tunnel.create":
            # This would need to be determined from the actual tool call
            return "tunnel.create"
        elif context.tool == "vpn.wireguard.toggle":
            return "vpn.up"
        else:
            return context.tool
    
    def _get_applied_restrictions(self, context: PolicyContext) -> List[str]:
        """Get list of restrictions applied to this operation."""
        restrictions = []
        
        if context.profile.policy.deny_sudo:
            restrictions.append("sudo_denied")
        
        if context.profile.policy.require_change_ticket_for:
            restrictions.append("change_ticket_required")
        
        if context.profile.policy.max_session_seconds < 3600:  # Less than 1 hour
            restrictions.append("session_timeout_limited")
        
        return restrictions
    
    @contextmanager
    def track_session(self, actor: str, profile_id: str):
        """Context manager to track active sessions."""
        try:
            self._start_session(actor, profile_id)
            yield
        finally:
            self._end_session(actor, profile_id)
    
    def _start_session(self, actor: str, profile_id: str) -> None:
        """Start tracking a new session."""
        if actor not in self._active_sessions:
            self._active_sessions[actor] = {}
        if actor not in self._session_start_times:
            self._session_start_times[actor] = {}
        
        self._active_sessions[actor][profile_id] = self._active_sessions[actor].get(profile_id, 0) + 1
        self._session_start_times[actor][profile_id] = time.time()
    
    def _end_session(self, actor: str, profile_id: str) -> None:
        """End tracking a session."""
        if actor in self._active_sessions and profile_id in self._active_sessions[actor]:
            self._active_sessions[actor][profile_id] = max(0, self._active_sessions[actor][profile_id] - 1)
            
            # Clean up if no active sessions
            if self._active_sessions[actor][profile_id] == 0:
                del self._active_sessions[actor][profile_id]
                if not self._active_sessions[actor]:
                    del self._active_sessions[actor]
        
        # Clean up session start times
        if actor in self._session_start_times and profile_id in self._session_start_times[actor]:
            del self._session_start_times[actor][profile_id]
            if not self._session_start_times[actor]:
                del self._session_start_times[actor]
    
    def get_session_stats(self) -> Dict[str, Dict[str, int]]:
        """Get current session statistics."""
        return {
            actor: {
                profile: {
                    "count": count,
                    "start_time": self._session_start_times.get(actor, {}).get(profile, 0)
                }
                for profile, count in profiles.items()
            }
            for actor, profiles in self._active_sessions.items()
        }


# Global policy engine instance
_policy_engine = PolicyEngine()


def enforce_policy(context: PolicyContext) -> PolicyDecision:
    """Convenience function to enforce policy using the global engine."""
    return _policy_engine.enforce_policy(context)


def get_policy_engine() -> PolicyEngine:
    """Get the global policy engine instance."""
    return _policy_engine

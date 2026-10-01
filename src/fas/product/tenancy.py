"""Tenant and role authorization primitives for production deployments."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class Role(str, Enum):
    READER = "reader"
    ANALYST = "analyst"
    ADMIN = "admin"

@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    subject: str
    role: Role = Role.READER

    def __post_init__(self) -> None:
        if not self.tenant_id or len(self.tenant_id) > 128:
            raise ValueError("invalid tenant_id")
        if not self.subject or len(self.subject) > 512:
            raise ValueError("invalid subject")

    def require(self, *roles: Role) -> None:
        if self.role not in roles:
            raise PermissionError("operation is not permitted for the current tenant role")

    def can_write(self) -> bool:
        return self.role in {Role.ANALYST, Role.ADMIN}

    def can_admin(self) -> bool:
        return self.role is Role.ADMIN

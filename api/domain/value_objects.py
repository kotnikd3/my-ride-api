"""Value Objects are compared based on their properties (values) rather than
identity. Two VOs are considered equal if all their attributes are the same."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TokenDataVO:
    updated: bool
    access_token: str
    refresh_token: str
    encrypted_session: Optional[str]
    refresh_expires_in: Optional[int]

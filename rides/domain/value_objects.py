from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    email: str
    preferred_username: str
    sub: str  # Keycloak ID

import uuid
from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    email: str
    name: str
    id: uuid.UUID  # Keycloak ID
    identity_provider: str
    contact_confirmed: Optional[bool] = False

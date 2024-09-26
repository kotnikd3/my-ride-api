import uuid
from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    email: str
    name: str
    id: uuid.UUID  # Keycloak ID
    contact_confirmed: Optional[bool] = False

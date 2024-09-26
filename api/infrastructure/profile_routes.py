from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Response, status

from api.domain.schemas import User
from api.domain.value_objects import TokenDataVO
from api.infrastructure.dependencies import (
    COOKIE_NAME,
    get_tokens,
    keycloak_validator,
)

profile_router = APIRouter(prefix='/profile', tags=['profile'])


@profile_router.get('', status_code=status.HTTP_200_OK)
async def profile(
    response: Response,
    tokens: Annotated[TokenDataVO, Depends(get_tokens)],
) -> Optional[User]:
    if tokens:
        if tokens.updated:
            response.set_cookie(
                key=COOKIE_NAME,
                value=tokens.encrypted_session,
                secure=True,
                httponly=True,
                max_age=tokens.refresh_expires_in,
            )

        claims = await keycloak_validator.authenticate_token(
            access_token=tokens.access_token,
        )
        return User(
            email=claims['email'],
            name=claims['name'],
            id=claims['sub'],
            contact_confirmed=claims['email_verified'],
        )
    return None

from typing import Annotated, Optional

from decouple import config
from fastapi import Depends
from fastapi.security import APIKeyCookie

from api.domain.value_objects import TokenDataVO
from api.infrastructure.authentication import KeycloakTokenValidator
from api.services.encryption import SessionEncryptor
from api.services.exceptions import AccessTokenExpiredError

COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)

keycloak_validator = KeycloakTokenValidator()
session_encryptor = SessionEncryptor()


async def get_session_or_none(
    session: str = Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))
) -> Optional[dict]:
    if session:
        return session_encryptor.decrypt(session=session)
    return None


async def get_tokens(
    tokens: Annotated[Optional[dict], Depends(get_session_or_none)],
) -> Optional[TokenDataVO]:
    """
    If tokens are not provided, return `None`.
    If access token is valid, return `TokenDataVO`.
    If access token is expired, try getting new tokens with refresh token. If
    this fails, raise InvalidTokenException, otherwise return `TokenDataVO`.
    """
    if not tokens:
        return None

    try:
        await keycloak_validator.authenticate_token(
            access_token=tokens['access_token'],
        )
        return TokenDataVO(
            updated=False,
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            encrypted_session=None,
            refresh_expires_in=None,
        )
    except AccessTokenExpiredError:
        new_tokens = await keycloak_validator.fetch_new_tokens(
            refresh_token=tokens['refresh_token'],
        )

        data = {
            'access_token': new_tokens['access_token'],
            'refresh_token': new_tokens['refresh_token'],
        }
        encrypted_session = session_encryptor.encrypt(data=data)

        return TokenDataVO(
            updated=True,
            access_token=new_tokens['access_token'],
            refresh_token=new_tokens['refresh_token'],
            encrypted_session=encrypted_session,
            refresh_expires_in=new_tokens['refresh_expires_in'],
        )

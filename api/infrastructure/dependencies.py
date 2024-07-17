from typing import Optional

from decouple import config
from fastapi import Depends, Response
from fastapi.security import APIKeyCookie

from api.infrastructure.authentication import KeycloakTokenValidator
from api.services.encryption import SessionEncryptor
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenException,
)

COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)

keycloak_validator = KeycloakTokenValidator()
session_encryptor = SessionEncryptor()


async def get_session_or_none(
    session: str = Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))
) -> Optional[dict]:
    if session:
        return session_encryptor.decrypt(session=session)
    return None


class GetTokens:
    def __init__(self, mandatory: Optional[bool] = True):
        self.mandatory = mandatory

    async def __call__(
        self,
        response: Response,
        tokens: dict = Depends(get_session_or_none),
    ) -> Optional[dict]:
        if tokens:
            try:
                keycloak_validator.authenticate_token(
                    access_token=tokens['access_token'],
                )
                return tokens
            except AccessTokenExpiredError:
                new_tokens = keycloak_validator.fetch_new_tokens(
                    refresh_token=tokens['refresh_token'],
                )

                selected_tokens = {
                    'access_token': new_tokens['access_token'],
                    'refresh_token': new_tokens['refresh_token'],
                }
                encrypted_session = session_encryptor.encrypt(
                    data=selected_tokens
                )
                response.set_cookie(
                    key=COOKIE_NAME,
                    value=encrypted_session,
                    secure=True,
                    httponly=True,
                    max_age=new_tokens['refresh_expires_in'],
                )

                return selected_tokens

        if self.mandatory:
            raise InvalidTokenException(
                'Unauthorized: missing session information',
                status_code=401,
            )
        return None


get_tokens = GetTokens()
get_tokens_or_none = GetTokens(mandatory=False)

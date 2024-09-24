from decouple import config
from jwcrypto import jwk
from jwcrypto.jwt import JWException, JWTExpired
from keycloak import KeycloakError, KeycloakOpenID
from keycloak.exceptions import KeycloakConnectionError

from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenException,
    ServiceUnavailableException,
)

OAUTH_SERVER_URL = config('OAUTH_SERVER_URL')
OAUTH_REALM_NAME = config('OAUTH_REALM_NAME')
OAUTH_CLIENT_ID = config('OAUTH_CLIENT_ID')
OAUTH_SECRET_KEY = config('OAUTH_SECRET_KEY')
OAUTH_ISSUER_URL = config('OAUTH_ISSUER_URL')


class KeycloakTokenValidator:
    def __init__(self):
        self.keycloak = KeycloakOpenID(
            server_url=OAUTH_SERVER_URL,
            realm_name=OAUTH_REALM_NAME,
            client_id=OAUTH_CLIENT_ID,
            client_secret_key=OAUTH_SECRET_KEY,
        )

        self._public_key = None

    async def _set_public_key(self) -> None:
        try:
            _public_key = await self.keycloak.a_public_key()
        except KeycloakConnectionError:
            self._public_key = None
        else:
            _public_key = (
                '-----BEGIN PUBLIC KEY-----\n'
                f'{_public_key}'
                '\n-----END PUBLIC KEY-----'
            )
            self._public_key = jwk.JWK.from_pem(_public_key.encode('utf-8'))

    async def public_key(self):
        if not self._public_key:
            await self._set_public_key()

            # Try again
            if not self._public_key:
                raise ServiceUnavailableException(
                    'Service Keycloak is unavailable'
                )

        return self._public_key

    async def authenticate_token(self, access_token: str) -> dict:
        check_claims = {
            'exp': None,
            'jti': None,
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_ISSUER_URL,
        }

        try:
            claims = await self.keycloak.a_decode_token(
                token=access_token,
                key=await self.public_key(),
                check_claims=check_claims,
            )
        except JWTExpired as error:
            raise AccessTokenExpiredError(repr(error))
        except JWException as error:
            raise InvalidTokenException(
                repr(error),
                status_code=403,
            )
        except ValueError:
            raise InvalidTokenException(
                'Forbidden: access token is not valid',
                status_code=403,
            )
        else:
            return claims

    async def get_tokens(self, code: str, redirect_uri: str) -> dict:
        try:
            return await self.keycloak.a_token(
                code=code,
                grant_type='authorization_code',
                redirect_uri=redirect_uri,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')
        except KeycloakError as error:
            raise InvalidTokenException(
                f'Forbidden: invalid code: {repr(error)}',
                status_code=403,
            )

    async def logout(self, refresh_token: str) -> None:
        try:
            await self.keycloak.a_logout(refresh_token=refresh_token)
        except KeycloakError as error:
            raise InvalidTokenException(
                f'Forbidden: something is wrong: {repr(error)}',
                status_code=403,
            )

    async def auth_url(self, scope: str, redirect_uri: str) -> str:
        try:
            return await self.keycloak.a_auth_url(
                scope=scope,
                redirect_uri=redirect_uri,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')
        except KeycloakError as error:
            raise InvalidTokenException(
                f'Forbidden: invalid redirect_uri: {repr(error)}',
                status_code=403,
            )

    async def fetch_new_tokens(self, refresh_token: str) -> dict:
        try:
            return await self.keycloak.a_refresh_token(
                refresh_token=refresh_token,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')
        except KeycloakError:
            raise InvalidTokenException(
                'Forbidden: refresh token expired',
                status_code=403,
            )

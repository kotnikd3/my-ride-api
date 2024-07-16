from decouple import config
from jwcrypto import jwk
from jwcrypto.jwt import JWException, JWTExpired
from keycloak import KeycloakOpenID, KeycloakPostError
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
OAUTH_REALM_URL = f'{OAUTH_SERVER_URL}/realms/{OAUTH_REALM_NAME}'


class KeycloakTokenValidator:
    def __init__(self):
        self.keycloak = KeycloakOpenID(
            server_url=OAUTH_SERVER_URL,
            realm_name=OAUTH_REALM_NAME,
            client_id=OAUTH_CLIENT_ID,
            client_secret_key=OAUTH_SECRET_KEY,
        )

        self._set_public_key()

    def _set_public_key(self) -> None:
        try:
            _public_key = self.keycloak.public_key()
        except KeycloakConnectionError:
            self._public_key = None
        else:
            _public_key = (
                '-----BEGIN PUBLIC KEY-----\n'
                f'{_public_key}'
                '\n-----END PUBLIC KEY-----'
            )
            self._public_key = jwk.JWK.from_pem(_public_key.encode('utf-8'))

    @property
    def public_key(self):
        if not self._public_key:
            # If Keycloak is not reachable when __init(self)__ is executed, try
            # reaching it (later) on every request
            self._set_public_key()
        return self._public_key

    def authenticate_token(self, access_token: str) -> dict:
        if not self.public_key:
            raise ServiceUnavailableException('Service Keycloak is unavailable')

        check_claims = {
            'exp': None,
            'jti': None,
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
        }

        try:
            claims = self.keycloak.decode_token(
                token=access_token,
                key=self.public_key,
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

    def get_tokens(self, code: str, redirect_uri: str) -> dict:
        try:
            return self.keycloak.token(
                code=code,
                grant_type='authorization_code',
                redirect_uri=redirect_uri,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')

    def logout(self, refresh_token: str) -> None:
        try:
            self.keycloak.logout(refresh_token=refresh_token)
        except KeycloakConnectionError:
            pass

    def auth_url(self, scope: str, redirect_uri: str) -> str:
        try:
            return self.keycloak.auth_url(
                scope=scope,
                redirect_uri=redirect_uri,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')

    def fetch_new_tokens(self, refresh_token: str) -> dict:
        try:
            return self.keycloak.refresh_token(refresh_token=refresh_token)
        except KeycloakPostError:
            raise InvalidTokenException(
                'Forbidden: refresh token expired',
                status_code=403,
            )
        except KeycloakConnectionError:
            raise ServiceUnavailableException('Service Keycloak is unavailable')

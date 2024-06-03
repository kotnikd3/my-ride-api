from decouple import config
from jwcrypto import jwk, jwt
from jwcrypto.jwt import JWException, JWTExpired
from keycloak import KeycloakOpenID, KeycloakPostError
from keycloak.exceptions import KeycloakConnectionError

from api.services.exceptions import InvalidTokenError, RefreshTokenExpiredError

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

    def _set_public_key(self):
        try:
            _public_key = self.keycloak.public_key()
        except KeycloakConnectionError:
            self.public_key = None
        else:
            _public_key = (
                '-----BEGIN PUBLIC KEY-----\n'
                f'{_public_key}'
                '\n-----END PUBLIC KEY-----'
            )
            self.public_key = jwk.JWK.from_pem(_public_key.encode('utf-8'))

    def _authenticate_token(self, token_string) -> dict:
        if self.public_key is None:
            # If Keycloak is not reachable when __init(self)__ is executed, try
            # reaching it on every request
            self._set_public_key()
            if self.public_key is None:
                raise Exception('Connection to Keycloak failed')

        check_claims = {
            'exp': None,
            'jti': None,
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
        }

        try:
            claims = self.keycloak.decode_token(
                token=token_string,
                key=self.public_key,
                check_claims=check_claims,
            )
        except jwt.JWException as error:
            raise error
        else:
            return claims

    def get_tokens(self, code: str, redirect_uri: str) -> dict:
        return self.keycloak.token(
            code=code,
            grant_type='authorization_code',
            redirect_uri=redirect_uri,
        )

    def logout(self, refresh_token: str) -> None:
        self.keycloak.logout(refresh_token=refresh_token)

    def auth_url(self, scope: str, redirect_uri: str) -> str:
        return self.keycloak.auth_url(scope=scope, redirect_uri=redirect_uri)

    def introspect(self, access_token: str) -> bool:
        response = self.keycloak.introspect(access_token)
        return response.get('active', False)

    def validate_tokens(self, access_token: str, refresh_token: str) -> dict:
        try:
            self._authenticate_token(token_string=access_token)
        except JWTExpired:
            try:
                return self.keycloak.refresh_token(refresh_token=refresh_token)
            except KeycloakPostError:
                raise RefreshTokenExpiredError()
        except JWException as error:
            raise InvalidTokenError(repr(error))

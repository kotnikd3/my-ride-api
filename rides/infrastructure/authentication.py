# TODO dependency
from api.infrastructure.authentication import KeycloakTokenValidator


class KeycloakTokenValidatorProxy(KeycloakTokenValidator):
    def __init__(self):
        super().__init__()

    def authenticate_token(self, access_token: str) -> dict:
        return super().authenticate_token(access_token=access_token)

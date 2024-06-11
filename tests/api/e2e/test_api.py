import json
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient
from jwcrypto import jwk, jwt

from api.infrastructure.authentication import (
    OAUTH_CLIENT_ID,
    OAUTH_REALM_URL,
    KeycloakTokenValidator,
)
from api.infrastructure.routes import (
    COOKIE_NAME,
    keycloak_validator,
    session_encryptor,
)
from api.infrastructure.servers import app


class TestControllerAsProxy(TestCase):
    def _get_signed_token(self, payload: dict) -> str:
        token = jwt.JWT(header={'alg': 'RS256'}, claims=payload)
        token.make_signed_token(self.private_jwk)
        signed_token = token.serialize()

        return signed_token

    @classmethod
    def setUpClass(cls) -> None:
        key = jwk.JWK.generate(kty='RSA', size=2048)
        # Export the keys
        public_key = key.export(private_key=False)
        private_key = key.export(private_key=True)

        # Parse the keys back into JWK objects for signing and verifying
        public_jwk = jwk.JWK.from_json(public_key)
        cls.private_jwk = jwk.JWK.from_json(private_key)

        validator = keycloak_validator
        validator.public_key = public_jwk

        cls.validator = validator

        cls.session_encryptor = session_encryptor

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def setUp(self):
        self.client = TestClient(app=app)

    def tearDown(self) -> None:
        app.dependency_overrides = {}

    def test_rides_without_session(self):
        # with self.assertRaises(HTTPException) as context:
        response = self.client.get('/rides')

        self.assertIn(
            'Unauthorized: missing session information',
            response.content.decode(),
        )
        self.assertEqual(401, response.status_code)
        self.assertNotIn(COOKIE_NAME, response.cookies)

    def test_rides(self):
        token_payload = {
            'exp': 9999999999,  # Max date
            'jti': 'The unique identifier for this token',
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
            'some': 'payload',
        }
        signed_token = self._get_signed_token(payload=token_payload)
        data = {
            'access_token': signed_token,
            'refresh_token': signed_token,
        }
        encrypted_token = self.session_encryptor.encrypt(data=data)

        response = self.client.get(
            '/rides',
            cookies={COOKIE_NAME: encrypted_token},
        )
        tokens = json.loads(response.content.decode())
        access_token = tokens['access_token']
        claims = self.validator.authenticate_token(access_token)

        self.assertEqual(data, tokens)
        self.assertEqual(signed_token, access_token)
        self.assertEqual(claims, token_payload)

    @patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
    def test_rides_fetch_new_tokens(self, mock_keycloak_fetch_new_tokens):
        new_token_payload = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'refresh_expires_in': None,
        }
        mock_keycloak_fetch_new_tokens.return_value = new_token_payload

        token_payload = {
            'exp': 1000000000,  # Expired
            'jti': 'The unique identifier for this token',
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
            'some': 'payload',
        }
        signed_token = self._get_signed_token(payload=token_payload)
        data = {
            'access_token': signed_token,
            'refresh_token': signed_token,
        }
        encrypted_token = self.session_encryptor.encrypt(data=data)

        response = self.client.get(
            '/rides',
            cookies={COOKIE_NAME: encrypted_token},
        )
        tokens = json.loads(response.content.decode())
        access_token = tokens['access_token']

        self.assertEqual(new_token_payload['access_token'], access_token)

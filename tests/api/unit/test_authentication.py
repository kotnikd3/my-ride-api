from unittest import TestCase
from unittest.mock import patch

from jwcrypto import jwk, jwt
from keycloak import KeycloakOpenID, KeycloakPostError

from api.infrastructure.authentication import (
    OAUTH_CLIENT_ID,
    OAUTH_REALM_URL,
    KeycloakTokenValidator,
)
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    InvalidTokenException,
)


class TestKeycloakTokenValidator(TestCase):
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

        validator = KeycloakTokenValidator()
        validator.public_key = public_jwk

        cls.validator = validator

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_authenticate_valid_token(self):
        payload = {
            'exp': 9999999999,  # Max date
            'jti': 'The unique identifier for this token',
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
            'some': 'payload',
        }
        signed_token = self._get_signed_token(payload=payload)

        claims = self.validator.authenticate_token(signed_token)
        self.assertEqual('payload', claims['some'])

    def test_authenticate_expired_token(self):
        payload = {
            'exp': 1000000000,  # Expired
            'jti': 'The unique identifier for this token',
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
        }
        signed_token = self._get_signed_token(payload=payload)

        # Check if 'Expired' is in the exception message
        with self.assertRaises(AccessTokenExpiredError) as context:
            self.validator.authenticate_token(signed_token)

        self.assertIn('Expired at 1000000000', str(context.exception))

    def test_authenticate_token_with_missing_jti(self):
        payload = {
            'exp': 9999999999,  # Max date
            'aud': OAUTH_CLIENT_ID,
            'iss': OAUTH_REALM_URL,
        }
        signed_token = self._get_signed_token(payload=payload)

        with self.assertRaises(InvalidTokenError) as context:
            self.validator.authenticate_token(signed_token)

        self.assertIn('Claim jti is missing', str(context.exception))

    def test_authenticate_token_with_wrong_aud(self):
        payload = {
            'exp': 9999999999,  # Max date
            'jti': 'The unique identifier for this token',
            'aud': 'WRONG_AUDIENCE',
            'iss': OAUTH_REALM_URL,
        }
        signed_token = self._get_signed_token(payload=payload)

        # Check if 'Expired' is in the exception message
        with self.assertRaises(InvalidTokenError) as context:
            self.validator.authenticate_token(signed_token)

        self.assertIn("Invalid 'aud' value.", str(context.exception))

    def test_authenticate_token_with_wrong_iss(self):
        payload = {
            'exp': 9999999999,  # Max date
            'jti': 'The unique identifier for this token',
            'aud': OAUTH_CLIENT_ID,
            'iss': 'WRONG_ISS',
        }
        signed_token = self._get_signed_token(payload=payload)

        with self.assertRaises(InvalidTokenError) as context:
            self.validator.authenticate_token(signed_token)

        self.assertIn("Invalid 'iss' value.", str(context.exception))

    @patch.object(KeycloakOpenID, 'refresh_token')
    def test_fetch_new_tokens_success(self, mock_keycloak_refresh_token):
        # Mock the keycloak instance and its refresh_token method
        # mock_keycloak = MockKeycloakOpenID.return_value
        mock_keycloak_refresh_token.return_value = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
        }

        # Call the fetch_new_tokens method
        tokens = self.validator.fetch_new_tokens(
            refresh_token='valid_refresh_token',
        )

        # Verify the tokens returned are as expected
        self.assertEqual(tokens['access_token'], 'new_access_token')
        self.assertEqual(tokens['refresh_token'], 'new_refresh_token')
        mock_keycloak_refresh_token.assert_called_once_with(
            refresh_token='valid_refresh_token',
        )

    @patch.object(KeycloakOpenID, 'refresh_token')
    def test_fetch_new_tokens_failure(self, mock_keycloak_refresh_token):
        # Mock the keycloak instance and refresh_token method to raise an error
        mock_keycloak_refresh_token.side_effect = KeycloakPostError()

        # Call the fetch_new_tokens method and expect an exception
        with self.assertRaises(InvalidTokenException) as context:
            self.validator.fetch_new_tokens(
                refresh_token='invalid_refresh_token',
            )

        # Verify the error message
        self.assertIn(
            'Forbidden: refresh token expired', str(context.exception)
        )
        mock_keycloak_refresh_token.assert_called_once_with(
            refresh_token='invalid_refresh_token',
        )

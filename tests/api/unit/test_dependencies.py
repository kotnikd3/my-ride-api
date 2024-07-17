from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from fastapi import Response

from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.dependencies import (
    COOKIE_NAME,
    get_session_or_none,
    get_tokens,
)
from api.services.encryption import SessionEncryptor
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenException,
)


def mocked_tokens():
    return {
        'access_token': 'mocked_access_token',
        'refresh_token': 'mocked_refresh_token',
        'refresh_expires_in': None,
    }


class TestDependencies(IsolatedAsyncioTestCase):
    @patch.object(SessionEncryptor, 'decrypt')
    async def test_get_session_or_none(self, mock_decrypt):
        mock_decrypt.return_value = mocked_tokens()

        session = await get_session_or_none('encrypted_string')
        self.assertEqual(session, mocked_tokens())

    async def test_get_session_or_none_session_not_valid(self):
        with self.assertRaises(InvalidTokenException) as context:
            await get_session_or_none('something')

        self.assertIn('InvalidToken()', str(context.exception))
        self.assertEqual(403, context.exception.status_code)

    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_get_tokens(self, mock_keycloak_authenticate_token):
        mock_keycloak_authenticate_token.return_value = None

        tokens = await get_tokens(Response(), mocked_tokens())
        self.assertEqual(tokens, mocked_tokens())

    @patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_get_tokens_new_tokens(
        self,
        mock_keycloak_authenticate_token,
        mock_keycloak_fetch_new_tokens,
    ):
        mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
        mock_keycloak_fetch_new_tokens.return_value = mocked_tokens()

        response = Response()
        new_tokens = await get_tokens(response, mocked_tokens())
        expected_tokens = {
            'access_token': 'mocked_access_token',
            'refresh_token': 'mocked_refresh_token',
        }

        self.assertIn(COOKIE_NAME, response.headers['set-cookie'])
        self.assertEqual(expected_tokens, new_tokens)

    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_get_tokens_not_valid_access_token(
        self,
        mock_keycloak_authenticate_token,
    ):
        mock_keycloak_authenticate_token.side_effect = InvalidTokenException(
            'Forbidden: access token is not valid', status_code=403
        )

        with self.assertRaises(InvalidTokenException) as context:
            await get_tokens(Response(), mocked_tokens())

        self.assertIn(
            'Forbidden: access token is not valid', str(context.exception)
        )
        self.assertEqual(403, context.exception.status_code)

    @patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_get_tokens_refresh_token_expired(
        self,
        mock_keycloak_authenticate_token,
        mock_keycloak_fetch_new_tokens,
    ):
        mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
        mock_keycloak_fetch_new_tokens.side_effect = InvalidTokenException(
            'Forbidden: refresh token expired', status_code=403
        )

        with self.assertRaises(InvalidTokenException) as context:
            await get_tokens(Response(), mocked_tokens())

        self.assertIn(
            'Forbidden: refresh token expired', str(context.exception)
        )
        self.assertEqual(403, context.exception.status_code)

    async def test_get_tokens_missing_session(self):
        with self.assertRaises(InvalidTokenException) as context:
            await get_tokens(Response(), None)  # Missing session

        self.assertIn(
            'Unauthorized: missing session information', str(context.exception)
        )
        self.assertEqual(401, context.exception.status_code)

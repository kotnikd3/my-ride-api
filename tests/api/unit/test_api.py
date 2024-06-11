from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from fastapi import Response
from fastapi.testclient import TestClient

from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.controllers import (
    COOKIE_NAME,
    app,
    session_required,
    tokens_required,
)
from api.services.encryption import SessionEncryptor
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    InvalidTokenException,
    RefreshTokenExpiredError,
)


def mocked_tokens():
    return {
        'access_token': 'mocked_access_token',
        'refresh_token': 'mocked_refresh_token',
        'refresh_expires_in': None,
    }


class TestController(TestCase):
    def setUp(self):
        self.client = TestClient(app=app)

    def tearDown(self) -> None:
        app.dependency_overrides = {}

    def test_index_without_cookie(self):
        response = self.client.get('/')

        self.assertEqual(200, response.status_code)
        self.assertIn('My ride', response.text)

    @patch.object(SessionEncryptor, 'decrypt')
    def test_index_with_cookie(self, mock_decrypt):
        mock_decrypt.return_value = mocked_tokens()

        response = self.client.get('/', cookies={COOKIE_NAME: 'mocked'})

        self.assertEqual(200, response.status_code)
        self.assertIn('My ride', response.text)
        self.assertIn('mocked_access_token', response.text)

    @patch.object(KeycloakTokenValidator, 'logout')
    def test_logout(self, mock_keycloak_logout):
        mock_keycloak_logout.return_value = None
        app.dependency_overrides[tokens_required] = mocked_tokens

        response = self.client.get(
            '/logout',
            cookies={COOKIE_NAME: 'mocked'},
            follow_redirects=False,
        )

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(
            app.url_path_for('index'), response.headers['location']
        )
        self.assertNotIn(COOKIE_NAME, response.cookies)

    @patch.object(KeycloakTokenValidator, 'get_tokens')
    def test_authorize(self, mock_keycloak_get_tokens):
        mock_keycloak_get_tokens.return_value = mocked_tokens()

        response = self.client.get(
            url='/authorize',
            params={'code': 'some_code'},
            allow_redirects=False,
        )

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(
            str(self.client.base_url) + '/', response.headers['location']
        )
        self.assertIn(COOKIE_NAME, response.cookies)

    def test_login(self):
        response = self.client.get(url='/login', allow_redirects=False)

        self.assertEqual(307, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertIn(
            'openid-connect/auth?client_id=', response.headers['location']
        )


class TestDependencies(IsolatedAsyncioTestCase):
    @patch.object(SessionEncryptor, 'decrypt')
    async def test_session_required(self, mock_decrypt):
        mock_decrypt.return_value = mocked_tokens()

        session = await session_required('encrypted_string')
        self.assertEqual(session, mocked_tokens())

    async def test_session_required_missing_session(self):
        with self.assertRaises(InvalidTokenException) as context:
            await session_required(None)  # Missing session

        self.assertIn(
            'Unauthorized: missing session information', str(context.exception)
        )
        self.assertEqual(401, context.exception.status_code)

    async def test_session_required_session_not_valid(self):
        with self.assertRaises(InvalidTokenException) as context:
            await session_required('something')

        self.assertIn('Forbidden: session is not valid', str(context.exception))
        self.assertEqual(403, context.exception.status_code)

    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_tokens_required(self, mock_keycloak_authenticate_token):
        mock_keycloak_authenticate_token.return_value = None

        tokens = await tokens_required(Response(), mocked_tokens())
        self.assertEqual(tokens, mocked_tokens())

    @patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_tokens_required_new_tokens(
        self,
        mock_keycloak_authenticate_token,
        mock_keycloak_fetch_new_tokens,
    ):
        mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
        mock_keycloak_fetch_new_tokens.return_value = mocked_tokens()

        response = Response()
        new_tokens = await tokens_required(response, mocked_tokens())
        expected_tokens = {
            'access_token': 'mocked_access_token',
            'refresh_token': 'mocked_refresh_token',
        }

        self.assertIn(COOKIE_NAME, response.headers['set-cookie'])
        self.assertEqual(expected_tokens, new_tokens)

    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_tokens_required_not_valid_access_token(
        self,
        mock_keycloak_authenticate_token,
    ):
        mock_keycloak_authenticate_token.side_effect = InvalidTokenError

        with self.assertRaises(InvalidTokenException) as context:
            await tokens_required(Response(), mocked_tokens())

        self.assertIn(
            'Forbidden: access token is not valid', str(context.exception)
        )
        self.assertEqual(403, context.exception.status_code)

    @patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
    @patch.object(KeycloakTokenValidator, 'authenticate_token')
    async def test_tokens_required_refresh_token_expired(
        self,
        mock_keycloak_authenticate_token,
        mock_keycloak_fetch_new_tokens,
    ):
        mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
        mock_keycloak_fetch_new_tokens.side_effect = RefreshTokenExpiredError

        with self.assertRaises(InvalidTokenException) as context:
            await tokens_required(Response(), mocked_tokens())

        self.assertIn(
            'Forbidden: refresh token expired', str(context.exception)
        )
        self.assertEqual(403, context.exception.status_code)

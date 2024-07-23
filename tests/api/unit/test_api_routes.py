from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import pytest
from httpx import AsyncClient

from api.infrastructure.api_routes import front_end
from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.dependencies import COOKIE_NAME, get_tokens
from api.main import app


def mocked_tokens():
    return {
        'access_token': 'mocked_access_token',
        'refresh_token': 'mocked_refresh_token',
        'refresh_expires_in': None,
    }


class TestApiRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = AsyncClient(app=app)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        app.dependency_overrides = {}

    @pytest.mark.skip('Not yet implemented')
    @patch.object(KeycloakTokenValidator, 'logout')
    async def test_logout(self, mock_keycloak_logout):
        mock_keycloak_logout.return_value = None
        app.dependency_overrides[get_tokens] = mocked_tokens

        self.client.cookies[COOKIE_NAME] = 'mocked'
        response = await self.client.get('/logout', follow_redirects=False)

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(front_end, response.headers['location'])
        self.assertNotIn(COOKIE_NAME, response.cookies)

    @pytest.mark.skip('Not yet implemented')
    @patch.object(KeycloakTokenValidator, 'get_tokens')
    async def test_authorize(self, mock_keycloak_get_tokens):
        mock_keycloak_get_tokens.return_value = mocked_tokens()

        response = await self.client.get(
            url='/authorize',
            params={'code': 'some_code'},
            follow_redirects=False,
        )

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(front_end, response.headers['location'])
        self.assertIn(COOKIE_NAME, response.cookies)

    @pytest.mark.skip('Not yet implemented')
    @patch.object(KeycloakTokenValidator, 'auth_url')
    async def test_login(self, mock_keycloak_auth_url):
        mock_keycloak_auth_url.return_value = '/openid-connect'

        response = await self.client.get(url='/login', follow_redirects=False)

        self.assertEqual(307, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertIn('/openid-connect', response.headers['location'])

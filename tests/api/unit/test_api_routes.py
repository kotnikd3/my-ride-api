from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

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


class TestApiRoutes(TestCase):
    def setUp(self):
        self.client = TestClient(app=app)

    def tearDown(self) -> None:
        app.dependency_overrides = {}

    @patch.object(KeycloakTokenValidator, 'logout')
    def test_logout(self, mock_keycloak_logout):
        mock_keycloak_logout.return_value = None
        app.dependency_overrides[get_tokens] = mocked_tokens

        self.client.cookies[COOKIE_NAME] = 'mocked'
        response = self.client.get('/logout', follow_redirects=False)

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(front_end, response.headers['location'])
        self.assertNotIn(COOKIE_NAME, response.cookies)

    @patch.object(KeycloakTokenValidator, 'get_tokens')
    def test_authorize(self, mock_keycloak_get_tokens):
        mock_keycloak_get_tokens.return_value = mocked_tokens()

        response = self.client.get(
            url='/authorize',
            params={'code': 'some_code'},
            follow_redirects=False,
        )

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(front_end, response.headers['location'])
        self.assertIn(COOKIE_NAME, response.cookies)

    @patch.object(KeycloakTokenValidator, 'auth_url')
    def test_login(self, mock_keycloak_auth_url):
        mock_keycloak_auth_url.return_value = '/openid-connect'

        response = self.client.get(url='/login', follow_redirects=False)

        self.assertEqual(307, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertIn('/openid-connect', response.headers['location'])

from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.dependencies import COOKIE_NAME, tokens_required
from api.main import app
from api.services.encryption import SessionEncryptor


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

        self.client.cookies[COOKIE_NAME] = 'mocked'
        response = self.client.get('/')

        self.assertEqual(200, response.status_code)
        self.assertIn('My ride', response.text)
        self.assertIn('mocked_access_token', response.text)

    @patch.object(KeycloakTokenValidator, 'logout')
    def test_logout(self, mock_keycloak_logout):
        mock_keycloak_logout.return_value = None
        app.dependency_overrides[tokens_required] = mocked_tokens

        self.client.cookies[COOKIE_NAME] = 'mocked'
        response = self.client.get('/logout', follow_redirects=False)

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
            follow_redirects=False,
        )

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertEqual(
            str(self.client.base_url) + '/', response.headers['location']
        )
        self.assertIn(COOKIE_NAME, response.cookies)

    @patch.object(KeycloakTokenValidator, 'auth_url')
    def test_login(self, mock_keycloak_auth_url):
        mock_keycloak_auth_url.return_value = '/openid-connect'

        response = self.client.get(url='/login', follow_redirects=False)

        self.assertEqual(307, response.status_code)
        self.assertTrue(response.is_redirect)
        self.assertIn('/openid-connect', response.headers['location'])

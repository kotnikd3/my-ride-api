import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from api.infrastructure.controllers import app, COOKIE_NAME
from api.services.exceptions import RefreshTokenExpiredError, InvalidTokenError
from api.infrastructure.authentication import KeycloakTokenValidator



client = TestClient(app)

# Mock KeycloakTokenValidator for testing
class MockKeycloakTokenValidator:
    def auth_url(self, redirect_uri, scope):
        return "http://mockauth.url"

    def get_tokens(self, code, redirect_uri):
        return {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
        }

    def authenticate_token(self, token_string):
        if token_string != "mock_access_token":
            raise InvalidTokenError("Invalid token")

    def fetch_new_tokens(self, refresh_token):
        if refresh_token == "mock_refresh_token":
            return {
                'access_token': 'new_mock_access_token',
                'refresh_token': 'new_mock_refresh_token',
            }
        raise RefreshTokenExpiredError("Refresh token expired")

    def logout(self, refresh_token):
        pass

app.dependency_overrides[KeycloakTokenValidator] = MockKeycloakTokenValidator

@pytest.fixture
def set_up():
    # Setup code for each test
    yield
    # Teardown code for each test
    app.dependency_overrides = {}

def test_login():
    response = client.get("/login")
    assert response.status_code == 200
    assert response.headers["location"] == "http://mockauth.url"
    assert response.is_redirect

def test_authorize():
    response = client.get("/authorize?code=mock_code")
    assert response.status_code == 302
    assert response.headers["location"] == client.base_url + "/"

    cookies = response.cookies
    assert COOKIE_NAME in cookies
    assert cookies[COOKIE_NAME] == {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }

def test_index_without_session():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"data": {}}

def test_index_with_session():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"data": {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }}

def test_logout():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["location"] == client.base_url + "/"

    cookies = response.cookies
    assert COOKIE_NAME not in cookies

def test_protected_endpoint_without_session():
    response = client.get("/rides")
    assert response.status_code == 401
    assert response.json() == {"detail": "Token is not valid"}

def test_protected_endpoint_with_session():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/rides")
    assert response.status_code == 200
    assert response.json() == {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }

def test_session_expiration():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token',
        'expires': (datetime.now() - timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S.%f')
    })

    response = client.get("/rides")
    assert response.status_code == 401
    assert response.json() == {"detail": "Session expired"}
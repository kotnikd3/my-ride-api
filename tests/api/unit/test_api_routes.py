from unittest.mock import AsyncMock, patch

from api.domain.value_objects import TokenDataVO
from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.dependencies import COOKIE_NAME, get_tokens
from api.main import app


def mocked_tokens():
    return {
        'access_token': 'mocked_access_token',
        'refresh_token': 'mocked_refresh_token',
        'refresh_expires_in': None,
    }


@patch.object(KeycloakTokenValidator, 'auth_url', new_callable=AsyncMock)
def test_login(mock_keycloak_auth_url, test_client):
    mock_keycloak_auth_url.return_value = '/openid-connect'

    response = test_client.get(url='/login', follow_redirects=False)

    assert 307 == response.status_code
    assert response.is_redirect
    assert '/openid-connect' in response.headers['location']


@patch.object(KeycloakTokenValidator, 'logout', new_callable=AsyncMock)
def test_logout(mock_keycloak_logout, test_client):
    mock_keycloak_logout.return_value = None
    app.dependency_overrides[get_tokens] = lambda: TokenDataVO(
        updated=True,
        access_token=mocked_tokens()['access_token'],
        refresh_token=mocked_tokens()['refresh_token'],
        encrypted_session=None,
        refresh_expires_in=mocked_tokens()['refresh_expires_in'],
    )

    response = test_client.get(
        '/logout?frontend_uri=https://frontend', follow_redirects=False
    )

    assert 302 == response.status_code
    assert response.is_redirect
    assert 'https://frontend' == response.headers['location']
    assert COOKIE_NAME not in response.cookies


@patch.object(KeycloakTokenValidator, 'get_tokens', new_callable=AsyncMock)
def test_authorize(mock_keycloak_get_tokens, test_client):
    mock_keycloak_get_tokens.return_value = mocked_tokens()

    response = test_client.get(
        url='/authorize?frontend_uri=https://frontend',
        params={'code': 'some_code'},
        follow_redirects=False,
    )

    assert 302 == response.status_code
    assert response.is_redirect
    assert 'https://frontend' == response.headers['location']
    assert COOKIE_NAME in response.cookies

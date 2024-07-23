from unittest.mock import AsyncMock, patch

import pytest

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


@pytest.mark.anyio
@patch.object(KeycloakTokenValidator, 'auth_url', new_callable=AsyncMock)
async def test_login(mock_keycloak_auth_url, async_client):
    mock_keycloak_auth_url.return_value = '/openid-connect'

    response = await async_client.get(url='/login', follow_redirects=False)

    assert 307 == response.status_code
    assert response.is_redirect
    assert '/openid-connect' in response.headers['location']


@pytest.mark.anyio
@patch.object(KeycloakTokenValidator, 'logout', new_callable=AsyncMock)
async def test_logout(mock_keycloak_logout, async_client):
    mock_keycloak_logout.return_value = None
    app.dependency_overrides[get_tokens] = mocked_tokens

    async_client.cookies[COOKIE_NAME] = 'mocked'
    response = await async_client.get('/logout', follow_redirects=False)

    assert 302 == response.status_code
    assert response.is_redirect
    assert front_end == response.headers['location']
    assert COOKIE_NAME not in response.cookies


@pytest.mark.anyio
@patch.object(KeycloakTokenValidator, 'get_tokens', new_callable=AsyncMock)
async def test_authorize(mock_keycloak_get_tokens, async_client):
    mock_keycloak_get_tokens.return_value = mocked_tokens()

    response = await async_client.get(
        url='/authorize',
        params={'code': 'some_code'},
        follow_redirects=False,
    )

    assert 302 == response.status_code
    assert response.is_redirect
    assert front_end == response.headers['location']
    assert COOKIE_NAME in response.cookies

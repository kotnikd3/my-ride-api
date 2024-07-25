from unittest.mock import patch

import pytest
from fastapi import Response

from api.domain.value_objects import TokenDataVO
from api.infrastructure.authentication import KeycloakTokenValidator
from api.infrastructure.dependencies import get_session_or_none, get_tokens
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


@pytest.mark.asyncio
@patch.object(SessionEncryptor, 'decrypt')
async def test_get_session_or_none(mock_decrypt):
    mock_decrypt.return_value = mocked_tokens()

    session = await get_session_or_none('encrypted_string')
    assert mocked_tokens() == session


@pytest.mark.asyncio
async def test_get_session_or_none_session_not_valid():
    with pytest.raises(InvalidTokenException) as context:
        await get_session_or_none('something')

    assert 'InvalidToken()' in str(context.value)
    assert 403 == context.value.status_code


@pytest.mark.asyncio
@patch.object(KeycloakTokenValidator, 'authenticate_token')
async def test_get_tokens(mock_keycloak_authenticate_token):
    mock_keycloak_authenticate_token.return_value = None

    tokens = await get_tokens(Response(), mocked_tokens())
    expected = TokenDataVO(
        updated=False,
        access_token=mocked_tokens()['access_token'],
        refresh_token=mocked_tokens()['refresh_token'],
        encrypted_session=None,
        refresh_expires_in=None,
    )
    assert expected == tokens


@pytest.mark.asyncio
@patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
@patch.object(KeycloakTokenValidator, 'authenticate_token')
async def test_get_tokens_new_tokens(
    mock_keycloak_authenticate_token,
    mock_keycloak_fetch_new_tokens,
):
    mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
    mock_keycloak_fetch_new_tokens.return_value = mocked_tokens()

    response = Response()
    result = await get_tokens(response, mocked_tokens())
    expected = TokenDataVO(
        updated=True,
        access_token=mocked_tokens()['access_token'],
        refresh_token=mocked_tokens()['refresh_token'],
        encrypted_session=None,
        refresh_expires_in=mocked_tokens()['refresh_expires_in'],
    )

    assert expected.updated == result.updated
    assert expected.access_token == result.access_token
    assert expected.refresh_token == result.refresh_token
    assert expected.refresh_expires_in == result.refresh_expires_in


@pytest.mark.asyncio
@patch.object(KeycloakTokenValidator, 'authenticate_token')
async def test_get_tokens_not_valid_access_token(
    mock_keycloak_authenticate_token,
):
    mock_keycloak_authenticate_token.side_effect = InvalidTokenException(
        'Forbidden: access token is not valid', status_code=403
    )

    with pytest.raises(InvalidTokenException) as context:
        await get_tokens(Response(), mocked_tokens())

    assert 'Forbidden: access token is not valid' in str(context.value)
    assert 403 == context.value.status_code


@pytest.mark.asyncio
@patch.object(KeycloakTokenValidator, 'fetch_new_tokens')
@patch.object(KeycloakTokenValidator, 'authenticate_token')
async def test_get_tokens_refresh_token_expired(
    mock_keycloak_authenticate_token,
    mock_keycloak_fetch_new_tokens,
):
    mock_keycloak_authenticate_token.side_effect = AccessTokenExpiredError
    mock_keycloak_fetch_new_tokens.side_effect = InvalidTokenException(
        'Forbidden: refresh token expired', status_code=403
    )

    with pytest.raises(InvalidTokenException) as context:
        await get_tokens(Response(), mocked_tokens())

    assert 'Forbidden: refresh token expired' in str(context.value)
    assert 403 == context.value.status_code


@pytest.mark.asyncio
async def test_get_tokens_missing_session():
    with pytest.raises(InvalidTokenException) as context:
        await get_tokens(Response(), None)  # Missing session

    assert 'Unauthorized: missing session information' in str(context.value)
    assert 401 == context.value.status_code

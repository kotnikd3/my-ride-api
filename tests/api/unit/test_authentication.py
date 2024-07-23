from unittest.mock import patch

import pytest
from jwcrypto import jwk, jwt
from keycloak import KeycloakOpenID, KeycloakPostError

from api.infrastructure.authentication import (
    OAUTH_CLIENT_ID,
    OAUTH_REALM_URL,
    KeycloakTokenValidator,
)
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenException,
)


def _get_signed_token(private_jwk: jwk.JWK, payload: dict) -> str:
    token = jwt.JWT(header={'alg': 'RS256'}, claims=payload)
    token.make_signed_token(private_jwk)
    signed_token = token.serialize()

    return signed_token


def _create_public_private_jwk_keys() -> tuple[jwk.JWK, jwk.JWK]:
    key = jwk.JWK.generate(kty='RSA', size=2048)
    # Export the keys
    public_key = key.export(private_key=False)
    private_key = key.export(private_key=True)

    # Parse the keys back into JWK objects for signing and verifying
    public_jwk = jwk.JWK.from_json(public_key)
    private_jwk = jwk.JWK.from_json(private_key)

    return public_jwk, private_jwk


@pytest.mark.asyncio
async def test_authenticate_valid_token():
    payload = {
        'exp': 9999999999,  # Max date
        'jti': 'The unique identifier for this token',
        'aud': OAUTH_CLIENT_ID,
        'iss': OAUTH_REALM_URL,
        'some': 'payload',
    }
    public_jwk, private_jwk = _create_public_private_jwk_keys()
    signed_token = _get_signed_token(private_jwk=private_jwk, payload=payload)

    validator = KeycloakTokenValidator()
    validator._public_key = public_jwk

    claims = await validator.authenticate_token(signed_token)
    assert 'payload' == claims['some']


@pytest.mark.asyncio
async def test_authenticate_expired_token():
    payload = {
        'exp': 1000000000,  # Expired
        'jti': 'The unique identifier for this token',
        'aud': OAUTH_CLIENT_ID,
        'iss': OAUTH_REALM_URL,
    }
    public_jwk, private_jwk = _create_public_private_jwk_keys()
    signed_token = _get_signed_token(private_jwk=private_jwk, payload=payload)

    validator = KeycloakTokenValidator()
    validator._public_key = public_jwk

    # Check if 'Expired' is in the exception message
    with pytest.raises(AccessTokenExpiredError) as context:
        await validator.authenticate_token(signed_token)

    assert 'Expired at 1000000000' in str(context.value)


@pytest.mark.asyncio
async def test_authenticate_token_with_missing_jti():
    payload = {
        'exp': 9999999999,  # Max date
        'aud': OAUTH_CLIENT_ID,
        'iss': OAUTH_REALM_URL,
    }
    public_jwk, private_jwk = _create_public_private_jwk_keys()
    signed_token = _get_signed_token(private_jwk=private_jwk, payload=payload)

    validator = KeycloakTokenValidator()
    validator._public_key = public_jwk

    with pytest.raises(InvalidTokenException) as context:
        await validator.authenticate_token(signed_token)

    assert 'Claim jti is missing' in str(context.value)


@pytest.mark.asyncio
async def test_authenticate_token_with_wrong_aud():
    payload = {
        'exp': 9999999999,  # Max date
        'jti': 'The unique identifier for this token',
        'aud': 'WRONG_AUDIENCE',
        'iss': OAUTH_REALM_URL,
    }
    public_jwk, private_jwk = _create_public_private_jwk_keys()
    signed_token = _get_signed_token(private_jwk=private_jwk, payload=payload)

    validator = KeycloakTokenValidator()
    validator._public_key = public_jwk

    with pytest.raises(InvalidTokenException) as context:
        await validator.authenticate_token(signed_token)

    assert "Invalid 'aud' value." in str(context.value)


@pytest.mark.asyncio
async def test_authenticate_token_with_wrong_iss():
    payload = {
        'exp': 9999999999,  # Max date
        'jti': 'The unique identifier for this token',
        'aud': OAUTH_CLIENT_ID,
        'iss': 'WRONG_ISS',
    }
    public_jwk, private_jwk = _create_public_private_jwk_keys()
    signed_token = _get_signed_token(private_jwk=private_jwk, payload=payload)

    validator = KeycloakTokenValidator()
    validator._public_key = public_jwk

    with pytest.raises(InvalidTokenException) as context:
        await validator.authenticate_token(signed_token)

    assert "Invalid 'iss' value." in str(context.value)


@pytest.mark.asyncio
@patch.object(KeycloakOpenID, 'a_refresh_token')
async def test_fetch_new_tokens_success(mock_keycloak_refresh_token):
    # Mock the keycloak instance and its refresh_token method
    # mock_keycloak = MockKeycloakOpenID.return_value
    mock_keycloak_refresh_token.return_value = {
        'access_token': 'new_access_token',
        'refresh_token': 'new_refresh_token',
    }

    validator = KeycloakTokenValidator()

    # Call the fetch_new_tokens method
    tokens = await validator.fetch_new_tokens(
        refresh_token='valid_refresh_token',
    )

    # Verify the tokens returned are as expected
    assert tokens['access_token'] == 'new_access_token'
    assert tokens['refresh_token'] == 'new_refresh_token'
    mock_keycloak_refresh_token.assert_called_once_with(
        refresh_token='valid_refresh_token',
    )


@pytest.mark.asyncio
@patch.object(KeycloakOpenID, 'a_refresh_token')
async def test_fetch_new_tokens_failure(mock_keycloak_refresh_token):
    # Mock the keycloak instance and refresh_token method to raise an error
    mock_keycloak_refresh_token.side_effect = KeycloakPostError()

    validator = KeycloakTokenValidator()

    # Call the fetch_new_tokens method and expect an exception
    with pytest.raises(InvalidTokenException) as context:
        await validator.fetch_new_tokens(refresh_token='invalid_refresh_token')

    # Verify the error message
    assert 'Forbidden: refresh token expired' in str(context.value)
    mock_keycloak_refresh_token.assert_called_once_with(
        refresh_token='invalid_refresh_token',
    )

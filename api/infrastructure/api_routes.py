from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse

from api.domain.value_objects import TokenDataVO
from api.infrastructure.dependencies import (
    COOKIE_NAME,
    get_tokens,
    keycloak_validator,
    session_encryptor,
)

api_rooter = APIRouter(prefix='', tags=['api'])


@api_rooter.get('/login', status_code=status.HTTP_307_TEMPORARY_REDIRECT)
async def login(request: Request) -> RedirectResponse:
    redirect_uri = str(request.url_for('authorize'))
    state = request.query_params.get('state')

    auth_url = await keycloak_validator.auth_url(
        scope='openid email',
        redirect_uri=redirect_uri,
        state=state,
    )

    # Redirect user to auth server
    return RedirectResponse(url=auth_url)  # Status code = 307


@api_rooter.get('/authorize', status_code=status.HTTP_302_FOUND)
async def authorize(request: Request) -> RedirectResponse:
    # Get the authorization code from the callback URL
    code = request.query_params.get('code')
    redirect_uri = str(request.url_for('authorize'))
    state = request.query_params.get('state')

    # Exchange the authorization code for a token
    tokens = await keycloak_validator.get_tokens(
        code=code,
        redirect_uri=redirect_uri,
    )

    # Save session storage space
    data = {
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
    }
    encrypted_session = session_encryptor.encrypt(data=data)

    # Redirect user back to the front end app (state)
    response = RedirectResponse(url=state, status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=encrypted_session,
        secure=True,
        httponly=True,
        max_age=tokens['refresh_expires_in'],
    )

    return response


@api_rooter.get('/logout', status_code=status.HTTP_302_FOUND)
async def logout(
    request: Request,
    tokens: Annotated[TokenDataVO, Depends(get_tokens)],
) -> RedirectResponse:
    if tokens:
        await keycloak_validator.logout(refresh_token=tokens.refresh_token)

    state = request.query_params.get('state')
    response = RedirectResponse(url=state, status_code=302)
    response.delete_cookie(key=COOKIE_NAME)

    return response

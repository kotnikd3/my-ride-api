import json
from typing import Annotated

import httpx
from decouple import config
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyCookie
from fastapi.templating import Jinja2Templates

from api.infrastructure.authentication import KeycloakTokenValidator
from api.services.encryption import SessionEncryptor
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenException,
    ServiceUnavailableException,
)

COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)
DEBUG = config('DEBUG', default=False, cast=bool)

app = FastAPI(debug=DEBUG)

keycloak_validator = KeycloakTokenValidator()
session_encryptor = SessionEncryptor()

templates = Jinja2Templates(directory="api/templates")


@app.exception_handler(InvalidTokenException)
@app.exception_handler(ServiceUnavailableException)
async def exception_handler(
    request: Request,
    exc: InvalidTokenException | ServiceUnavailableException,
) -> None:
    delete_cookie = (
        f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
    )
    raise HTTPException(
        detail=str(exc),
        status_code=exc.status_code,
        headers={'set-cookie': delete_cookie},
    )


async def session_required(
    session: str = Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))
) -> dict:
    if not session:
        raise InvalidTokenException(
            'Unauthorized: missing session information',
            status_code=401,
        )
    return session_encryptor.decrypt(session=session)


async def tokens_required(
    response: Response,
    tokens: dict = Depends(session_required),
) -> dict:
    try:
        keycloak_validator.authenticate_token(
            access_token=tokens['access_token'],
        )
        return tokens
    except AccessTokenExpiredError:
        new_tokens = keycloak_validator.fetch_new_tokens(
            refresh_token=tokens['refresh_token'],
        )

        selected_tokens = {
            'access_token': new_tokens['access_token'],
            'refresh_token': new_tokens['refresh_token'],
        }
        encrypted_session = session_encryptor.encrypt(data=selected_tokens)
        response.set_cookie(
            key=COOKIE_NAME,
            value=encrypted_session,
            secure=True,
            httponly=True,
            max_age=new_tokens['refresh_expires_in'],
        )

        return selected_tokens


@app.get('/login')
def login(request: Request) -> RedirectResponse:
    redirect_uri = str(request.url_for('authorize'))

    auth_url = keycloak_validator.auth_url(
        redirect_uri=redirect_uri,
        scope='openid email',
    )

    return RedirectResponse(url=auth_url)


@app.get('/authorize')
def authorize(request: Request) -> RedirectResponse:
    # Get the authorization code from the callback URL
    code = request.query_params.get('code')
    redirect_uri = str(request.url_for('authorize'))

    # Exchange the authorization code for a token
    tokens = keycloak_validator.get_tokens(
        code=code,
        redirect_uri=redirect_uri,
    )

    # Save session storage space
    selected_tokens = {
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
    }
    encrypted_session = session_encryptor.encrypt(data=selected_tokens)

    # TODO optional
    response = RedirectResponse(url=request.url_for('index'), status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=encrypted_session,
        secure=True,
        httponly=True,
        max_age=tokens['refresh_expires_in'],
    )

    return response


@app.get('/logout')
def logout(tokens: Annotated[dict, Depends(tokens_required)]):
    keycloak_validator.logout(refresh_token=tokens['refresh_token'])

    response = RedirectResponse(url=app.url_path_for('index'), status_code=302)
    response.delete_cookie(key=COOKIE_NAME)

    return response


@app.get('/')
async def index(request: Request):
    encrypted_session = request.cookies.get(COOKIE_NAME)

    tokens = None
    if encrypted_session:
        tokens = session_encryptor.decrypt(session=encrypted_session)
        tokens = json.dumps(tokens, sort_keys=True, indent=4)

    return templates.TemplateResponse(request, 'index.html', {'data': tokens})


@app.get('/rides/{path:path}')
async def proxy(path: str, tokens: Annotated[dict, Depends(tokens_required)]):
    target_url = (
        f'http://rides:8000/rides/{path}' if path else 'http://rides:8000/rides'
    )
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    # Send request to Rides microservice
    async with httpx.AsyncClient() as client:
        response = await client.get(target_url, headers=headers)

    return response.json()

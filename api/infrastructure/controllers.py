from decouple import config
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from api.infrastructure.authentication import (
    KeycloakTokenValidator,
)
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    RefreshTokenExpiredError,
)
from starlette.middleware.sessions import SessionMiddleware


COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)

app = FastAPI(debug=config('DEBUG', default=False, cast=bool))

app.add_middleware(
    SessionMiddleware,
    secret_key=config('SECRET_KEY'),
    session_cookie=COOKIE_NAME,
    https_only=True,
    max_age=1800,  # Same as max age for refresh token in Keycloak
)


templates = Jinja2Templates(directory="api/templates")
keycloak_validator = KeycloakTokenValidator()


class InvalidTokenException(Exception):
    pass


@app.exception_handler(InvalidTokenException)
async def exception_handler(
    request: Request, exc: InvalidTokenException
) -> Response:
    # TODO detail status code headers
    raise HTTPException(
        status_code=401,
        detail='Token is not valid',
        headers={'set-cookie': f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'},
    )


async def session_required(request: Request):
    if not (request.session or COOKIE_NAME in request.session):
        raise InvalidTokenException()
    return request.session.get(COOKIE_NAME)


async def tokens_required(request: Request, tokens = Depends(session_required)):
    try:
        keycloak_validator.authenticate_token(
            access_token=tokens['access_token'],
        )
        return tokens
    except InvalidTokenError:
        raise InvalidTokenException()
    except AccessTokenExpiredError:
        try:
            new_tokens = keycloak_validator.fetch_new_tokens(
                refresh_token=tokens['refresh_token'],
            )

            selected_tokens = {
                'access_token': new_tokens['access_token'],
                'refresh_token': new_tokens['refresh_token'],
            }
            request.session[COOKIE_NAME] = selected_tokens
            return selected_tokens
        except RefreshTokenExpiredError:
            raise InvalidTokenException()


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

    request.session[COOKIE_NAME] = selected_tokens

    return RedirectResponse(url=request.url_for('index'), status_code=302)


@app.get('/logout')
def logout(request: Request, tokens=Depends(tokens_required)):
    keycloak_validator.logout(refresh_token=tokens['refresh_token'])

    request.session.clear()

    return RedirectResponse(url=request.url_for('index'), status_code=302)


@app.get('/')
async def index(request: Request):
    tokens = request.session.get(COOKIE_NAME, {})

    return templates.TemplateResponse(
        'index.html', {'request': request, 'data': tokens}
    )


@app.get('/rides')
async def rides(tokens=Depends(tokens_required)):
    return tokens

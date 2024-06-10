from decouple import config
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from api.infrastructure.authentication import (
    KeycloakTokenValidator,
)
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    RefreshTokenExpiredError,
    InvalidTokenException,
)
from starlette.middleware.sessions import SessionMiddleware


COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)
SECRET_KEY = config('SECRET_KEY', default='SL0m0IqlK0O8', cast=str)
DEBUG = config('DEBUG', default=False, cast=bool)


app = FastAPI(debug=DEBUG)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie=COOKIE_NAME,
    https_only=True,
    max_age=1800,  # Same as max age for refresh token in Keycloak
)


templates = Jinja2Templates(directory="api/templates")
keycloak_validator = KeycloakTokenValidator()


@app.exception_handler(InvalidTokenException)
async def exception_handler(
    request: Request,
    exc: InvalidTokenException,
) -> None:
    request.session.clear()
    raise HTTPException(
        detail=str(exc),
        status_code=exc.status_code,
    )


async def session_required(request: Request):
    if not (request.session or COOKIE_NAME in request.session):
        raise InvalidTokenException(
            'Unauthorized: session is not valid',
            status_code=401,
        )
    return request.session.get(COOKIE_NAME)


async def tokens_required(
    request: Request,
    tokens: dict = Depends(session_required),
):
    try:
        keycloak_validator.authenticate_token(
            access_token=tokens['access_token'],
        )
        return tokens
    except InvalidTokenError:
        raise InvalidTokenException(
            'Forbidden: access token is not valid',
            status_code=403,
        )
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
            raise InvalidTokenException(
                'Forbidden: refresh token expired',
                status_code=403,
            )


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

    # TODO optional: redirect user to originally requested url
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
    # Send request to Rides microservice
    return tokens

import json

from decouple import config
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyCookie
from fastapi.templating import Jinja2Templates

from api.infrastructure.authentication import (
    KeycloakTokenValidator,
    SessionValidator,
)
from api.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    RefreshTokenExpiredError,
)

COOKIE_NAME = config('COOKIE_NAME', default='my-ride', cast=str)

cookie_values = {
    'key': COOKIE_NAME,
    'secure': True,
    'httponly': True,
}

SET_COOKIE_HEADER = (
    f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
)

app = FastAPI(debug=config('DEBUG', default=False, cast=bool))

cookie_sec = APIKeyCookie(name=COOKIE_NAME, auto_error=False)


templates = Jinja2Templates(directory="api/templates")
keycloak_validator = KeycloakTokenValidator()
session_validator = SessionValidator(fernet_key=config('SECRET_KEY'))


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
        headers={'set-cookie': SET_COOKIE_HEADER},
    )


from starlette.middleware.sessions import SessionMiddleware
app.add_middleware(SessionMiddleware, secret_key="your_secret_key", session_cookie=COOKIE_NAME, https_only=True, max_age=1800)


async def session_another_required(request: Request):
    if not (request.session or COOKIE_NAME in request.session):
        raise InvalidTokenException()
    return request.session.get(COOKIE_NAME)

async def tokens_another_required(request: Request, tokens = Depends(session_another_required)):
    try:
        keycloak_validator.authenticate_token(
            token_string=tokens['access_token'],
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

# async def session_required(session: str = Depends(cookie_sec)):
#     if not session:
#         raise InvalidTokenException()
#
#     try:
#         return session_validator.decrypt(session)
#     except InvalidTokenError:
#         raise InvalidTokenException()
#
#
# async def tokens_required(
#     response: Response, tokens: dict = Depends(session_required)
# ):
#     try:
#         keycloak_validator.authenticate_token(
#             token_string=tokens['access_token'],
#         )
#         return tokens
#     except InvalidTokenError:
#         raise InvalidTokenException()
#     except AccessTokenExpiredError:
#         try:
#             new_tokens = keycloak_validator.fetch_new_tokens(
#                 refresh_token=tokens['refresh_token'],
#             )
#
#             selected_tokens = {
#                 'access_token': new_tokens['access_token'],
#                 'refresh_token': new_tokens['refresh_token'],
#             }
#             encrypted_tokens = session_validator.encrypt(selected_tokens)
#             response.set_cookie(
#                 key=COOKIE_NAME,
#                 value=encrypted_tokens,
#                 secure=True,
#                 httponly=True,
#                 max_age=new_tokens['refresh_expires_in'],
#             )
#             return selected_tokens
#         except RefreshTokenExpiredError:
#             raise InvalidTokenException()


@app.get('/login')
def login(request: Request) -> RedirectResponse:
    redirect_uri = str(request.url_for('authorize'))

    auth_url = keycloak_validator.auth_url(
        redirect_uri=redirect_uri,
        scope='openid email',
    )

    return RedirectResponse(url=auth_url)


@app.get('/authorize')
def authorize(request: Request):
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

    # encrypted_tokens = session_validator.encrypt(selected_tokens)

    response = RedirectResponse(url=request.url_for('index'), status_code=302)
    # response.set_cookie(
    #     key=COOKIE_NAME,
    #     value=encrypted_tokens,
    #     secure=True,
    #     httponly=True,
    #     max_age=tokens['refresh_expires_in'],
    # )
    request.session[COOKIE_NAME] = selected_tokens

    return response


@app.get('/logout')
def logout(request: Request, tokens=Depends(tokens_another_required)):
    keycloak_validator.logout(refresh_token=tokens['refresh_token'])

    request.session.clear()

    return RedirectResponse(url=request.url_for('index'), status_code=302)
    # response = RedirectResponse(url=app.url_path_for('index'))
    # response.delete_cookie(key=COOKIE_NAME)


@app.get('/')
async def index(request: Request):
    # encrypted_tokens = request.cookies.get(COOKIE_NAME)

    # tokens = None
    # if encrypted_tokens:
    #     tokens = session_validator.decrypt(encrypted_tokens)
    #     tokens = json.dumps(tokens, sort_keys=True, indent=4)

    tokens = request.session.get(COOKIE_NAME, {})
    return templates.TemplateResponse(
        'index.html', {'request': request, 'data': tokens}
    )


@app.get('/rides')
async def rides(tokens=Depends(tokens_another_required)):
    return tokens

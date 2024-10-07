from decouple import config
from fastapi import FastAPI, HTTPException, Request

from api.infrastructure.api_routes import api_rooter
from api.infrastructure.dependencies import COOKIE_NAME
from api.infrastructure.profile_routes import profile_router
from api.infrastructure.ride_routes import ride_router
from api.services.exceptions import (
    InvalidTokenException,
    ServiceUnavailableException,
)

DEBUG = config('DEBUG', default=False, cast=bool)

app = FastAPI(debug=DEBUG)
app.include_router(api_rooter)
app.include_router(ride_router)
app.include_router(profile_router)


if DEBUG:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=['http://localhost:5173'],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.exception_handler(InvalidTokenException)
@app.exception_handler(ServiceUnavailableException)
async def exception_handler(
    request: Request,
    exc: InvalidTokenException | ServiceUnavailableException,
) -> None:
    arguments = {'detail': str(exc), 'status_code': exc.status_code}

    if isinstance(exc, InvalidTokenException):
        # Delete cookies in case of InvalidTokenException
        arguments['headers'] = {
            'set-cookie': f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'  # noqa: E501
        }

    raise HTTPException(**arguments)

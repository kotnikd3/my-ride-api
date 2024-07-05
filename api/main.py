from decouple import config
from fastapi import FastAPI, HTTPException, Request

from api.infrastructure.api_routes import api_rooter
from api.infrastructure.dependencies import COOKIE_NAME
from api.infrastructure.ride_routes import ride_rooter
from api.services.exceptions import (
    InvalidTokenException,
    ServiceUnavailableException,
)

DEBUG = config('DEBUG', default=False, cast=bool)

app = FastAPI(debug=DEBUG)
app.include_router(api_rooter)
app.include_router(ride_rooter)


@app.exception_handler(InvalidTokenException)
@app.exception_handler(ServiceUnavailableException)
async def exception_handler(
    request: Request,
    exc: InvalidTokenException | ServiceUnavailableException,
) -> None:
    arguments = {
        'detail': str(exc),
        'status_code': exc.status_code,
        'headers': {
            'set-cookie': f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'  # noqa: E501
        },
    }
    if isinstance(exc, ServiceUnavailableException):
        # Don't delete cookies in a case of ServiceUnavailableException
        del arguments['headers']  # Delete key

    raise HTTPException(**arguments)

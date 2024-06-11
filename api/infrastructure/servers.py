from decouple import config
from fastapi import FastAPI, HTTPException, Request

from api.infrastructure.routes import COOKIE_NAME, api_router
from api.services.exceptions import InvalidTokenException

DEBUG = config('DEBUG', default=False, cast=bool)


app = FastAPI(debug=DEBUG)
app.include_router(api_router)


@app.exception_handler(InvalidTokenException)
async def exception_handler(
    request: Request,
    exc: InvalidTokenException,
) -> None:
    delete_cookie = (
        f'{COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
    )
    raise HTTPException(
        detail=str(exc),
        status_code=exc.status_code,
        headers={'set-cookie': delete_cookie},
    )

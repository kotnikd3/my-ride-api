from typing import Annotated, Any, Dict, Optional

import httpx
from decouple import config
from fastapi import APIRouter, Body, Depends, Request, Response

from api.domain.value_objects import TokenDataVO
from api.infrastructure.dependencies import COOKIE_NAME, get_tokens
from api.services.exceptions import ServiceUnavailableException

RIDES_SERVICE = config('RIDE_SERVICE')

rides_router = APIRouter(prefix='/rides', tags=['rides'])


@rides_router.api_route(
    '/{path:path}',
    methods=['GET', 'POST', 'PUT', 'DELETE'],
)
async def proxy_request(
    request: Request,
    path: str,
    tokens: Annotated[TokenDataVO, Depends(get_tokens)],
    body: Optional[Dict[str, Any]] = Body(None),
) -> Response:
    """Send request to Ride API and return response.
    If tokens have been updated, update cookies in the response."""

    # Construct the target URL
    target_url = (
        f'{RIDES_SERVICE}/rides/{path}' if path else f'{RIDES_SERVICE}/rides'
    )
    if request.query_params:
        target_url = f'{target_url}?{request.query_params}'

    headers = (
        {'Authorization': f'Bearer {tokens.access_token}'} if tokens else None
    )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                json=body,
                timeout=10,  # Because of Cloud Run cold starts
            )
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    response = Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )

    if tokens and tokens.updated:
        response.set_cookie(
            key=COOKIE_NAME,
            value=tokens.encrypted_session,
            secure=True,
            httponly=True,
            max_age=tokens.refresh_expires_in,
        )

    return response

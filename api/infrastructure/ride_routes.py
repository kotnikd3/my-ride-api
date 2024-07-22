from datetime import date
from typing import Annotated, Any, Dict, Optional
from urllib.parse import urlencode
from uuid import UUID

import httpx
from decouple import config
from fastapi import APIRouter, Body, Depends, Response, status

from api.infrastructure.dependencies import get_tokens, get_tokens_or_none
from api.services.exceptions import ServiceUnavailableException

RIDE_SERVICE = config('RIDE_SERVICE')

ride_router = APIRouter(prefix='/ride', tags=['ride'])


async def make_request(
    method: str,
    url: str,
    access_token: str = None,
    json: Optional[Dict[str, Any]] = None,
) -> Response:
    headers = (
        {'Authorization': f'Bearer {access_token}'} if access_token else None
    )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method, url=url, headers=headers, json=json, timeout=4
            )
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )


@ride_router.get('', status_code=status.HTTP_200_OK)
async def get_all() -> Response:
    target_url = f'{RIDE_SERVICE}/ride'

    return await make_request('GET', target_url)


@ride_router.get('/by_user', status_code=status.HTTP_200_OK)
async def get_all_by_user_id(
    tokens: Annotated[dict, Depends(get_tokens)],
) -> Response:
    target_url = f'{RIDE_SERVICE}/ride/by_user'

    return await make_request(
        'GET', target_url, access_token=tokens['access_token']
    )


@ride_router.get('/by_location', status_code=status.HTTP_200_OK)
async def get_all_by_location(
    departure: date,
    origin: Optional[str] = None,
    destination: Optional[str] = None,
) -> Response:
    query_params = {
        'origin': origin,
        'destination': destination,
        'departure': departure.isoformat(),  # Convert date to ISO format string
    }
    target_url = f"{RIDE_SERVICE}/ride/by_location?{urlencode(query_params)}"

    return await make_request('GET', target_url)


@ride_router.get('/{ride_id}', status_code=status.HTTP_200_OK)
async def get_one_by_id(
    ride_id: UUID,
    tokens: Annotated[dict, Depends(get_tokens_or_none)],
) -> Response:
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'

    access_token = tokens['access_token'] if tokens else None

    return await make_request(
        'GET',
        target_url,
        access_token=access_token,
    )


@ride_router.post('')
async def create(
    body: Annotated[dict, Body],
    tokens: Annotated[dict, Depends(get_tokens)],
) -> Response:
    target_url = f'{RIDE_SERVICE}/ride'

    return await make_request(
        'POST', target_url, access_token=tokens['access_token'], json=body
    )


@ride_router.put('/{ride_id}', status_code=status.HTTP_200_OK)
async def put(
    ride_id: UUID,
    body: Annotated[dict, Body],
    tokens: Annotated[dict, Depends(get_tokens)],
) -> Response:
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'

    return await make_request(
        'PUT', target_url, access_token=tokens['access_token'], json=body
    )


@ride_router.delete('/{ride_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    ride_id: UUID,
    tokens: Annotated[dict, Depends(get_tokens)],
) -> Response:
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'

    return await make_request(
        'DELETE', target_url, access_token=tokens['access_token']
    )

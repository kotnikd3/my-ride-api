from typing import Annotated

import httpx
from decouple import config
from fastapi import APIRouter, Depends

from api.infrastructure.dependencies import tokens_required
from api.services.exceptions import ServiceUnavailableException

ride_rooter = APIRouter(prefix='/ride', tags=['ride'])

RIDE_SERVICE = config('RIDE_SERVICE')


@ride_rooter.get('/{path:path}')
async def proxy(path: str, tokens: Annotated[dict, Depends(tokens_required)]):
    target_url = f'{RIDE_SERVICE}/{path}' if path else RIDE_SERVICE
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, headers=headers, timeout=4)
    except httpx.TimeoutException as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )
    except httpx.ConnectError as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends

from api.infrastructure.dependencies import tokens_required

ride_rooter = APIRouter(prefix='/ride', tags=['ride'])


@ride_rooter.get('/{path:path}')
async def proxy(path: str, tokens: Annotated[dict, Depends(tokens_required)]):
    target_url = (
        f'http://rides:8000/ride/{path}' if path else 'http://rides:8000/ride'
    )
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    # Send request to Rides microservice
    async with httpx.AsyncClient() as client:
        response = await client.get(target_url, headers=headers)

    return response.json()

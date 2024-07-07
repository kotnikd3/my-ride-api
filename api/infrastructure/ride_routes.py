from datetime import date
from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import UUID

import httpx
from decouple import config
from fastapi import APIRouter, Body, Depends, status

from api.infrastructure.dependencies import tokens_required
from api.services.exceptions import ServiceUnavailableException

RIDE_SERVICE = config('RIDE_SERVICE')

ride_router = APIRouter(prefix='/ride', tags=['ride'])


@ride_router.get('', status_code=status.HTTP_200_OK)
async def get_all() -> Any:
    target_url = f'{RIDE_SERVICE}/ride'

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, timeout=4)
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.get('/by_user', status_code=status.HTTP_200_OK)
async def get_all_by_user_id(
    tokens: Annotated[dict, Depends(tokens_required)],
) -> Any:
    target_url = f'{RIDE_SERVICE}/ride/by_user'
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, headers=headers, timeout=4)
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.get('/by_location', status_code=status.HTTP_200_OK)
async def get_all_by_location(
    origin: str,
    destination: str,
    departure: date,
) -> Any:
    query_params = {
        'origin': origin,
        'destination': destination,
        'departure': departure.isoformat(),  # Convert date to ISO format string
    }
    target_url = f"{RIDE_SERVICE}/ride/by_location?{urlencode(query_params)}"

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, timeout=4)
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.get('/{ride_id}', status_code=status.HTTP_200_OK)
async def get_one_by_id(ride_id: UUID):
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.get(target_url, timeout=4)
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.post('', status_code=status.HTTP_201_CREATED)
async def create(
    body: Annotated[dict, Body],
    tokens: Annotated[dict, Depends(tokens_required)],
) -> Any:
    target_url = f'{RIDE_SERVICE}/ride'
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.post(
                target_url, headers=headers, json=body, timeout=4
            )
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.put('/{ride_id}', status_code=status.HTTP_200_OK)
async def put(
    ride_id: UUID,
    body: Annotated[dict, Body],
    tokens: Annotated[dict, Depends(tokens_required)],
) -> Any:
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            response = await client.put(
                target_url, headers=headers, json=body, timeout=4
            )
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    return response.json()


@ride_router.delete('/{ride_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    ride_id: UUID,
    tokens: Annotated[dict, Depends(tokens_required)],
) -> None:
    target_url = f'{RIDE_SERVICE}/ride/{ride_id}'
    headers = {'Authorization': f'Bearer {tokens['access_token']}'}

    try:
        # Send request to Rides microservice
        async with httpx.AsyncClient() as client:
            await client.delete(target_url, headers=headers, timeout=4)
    except (httpx.TimeoutException, httpx.ConnectError) as error:
        raise ServiceUnavailableException(
            f'Ride service is unavailable: {repr(error)}'
        )

    # TODO if response == 404, then return something else
    return None

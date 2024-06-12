from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from rides.infrastructure.authentication import KeycloakTokenValidatorProxy
from rides.services.exceptions import (
    AccessTokenExpiredError,
    InvalidTokenError,
    InvalidTokenException,
    KeycloakNotReachableError,
    ServiceUnreachableException,
)

http_bearer_token = HTTPBearer()


rides_router = APIRouter(
    prefix='/rides',
    tags=['rides'],
)

keycloak_validator = KeycloakTokenValidatorProxy()


async def decode_access_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials, Depends(http_bearer_token)
    ]
) -> dict:
    access_token = credentials.credentials

    try:
        claims = keycloak_validator.authenticate_token(
            access_token=access_token,
        )
        return claims
    except InvalidTokenError:
        raise InvalidTokenException(
            'Forbidden: access token is not valid',
            status_code=403,
        )
    except AccessTokenExpiredError:
        raise InvalidTokenException(
            'Forbidden: access token expired',
            status_code=403,
        )
    except KeycloakNotReachableError as error:
        raise ServiceUnreachableException(error)


@rides_router.get('')
async def rides(claims: Annotated[dict, Depends(decode_access_token)]):
    # Send request to Rides microservice
    return claims

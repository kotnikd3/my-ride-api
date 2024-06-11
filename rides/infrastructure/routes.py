from fastapi import APIRouter, Depends

# TODO Dependency
from api.infrastructure.routes import tokens_required

rides_router = APIRouter(prefix='/proxy', tags=['proxy'])


@rides_router.get('')
async def rides(tokens: dict = Depends(tokens_required)):
    # Send request to Rides microservice
    return tokens

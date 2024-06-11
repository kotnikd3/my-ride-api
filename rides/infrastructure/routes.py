from fastapi import APIRouter

rides_router = APIRouter(prefix='/rides', tags=['rides'])


@rides_router.get('')
async def rides():
    # Send request to Rides microservice
    return {'id': 123}

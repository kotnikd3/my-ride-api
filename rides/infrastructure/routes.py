from fastapi import APIRouter, Depends, FastAPI
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


rides_router = APIRouter(
    prefix='/rides',
    tags=['rides'],
    dependencies=[Depends(oauth2_scheme)],
)


@rides_router.get('')
async def rides(access_token):
    # Send request to Rides microservice
    return {'id': access_token}


header_scheme = APIKeyHeader(name='Authorization', auto_error=False)


@rides_router.get("/items")
async def read_items(key: str = Depends(header_scheme)):
    return {"key": key}

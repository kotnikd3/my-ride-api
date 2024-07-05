import json

from cryptography.fernet import Fernet
from decouple import config

from api.services.exceptions import InvalidTokenException

FERNET_KEY = config(
    'FERNET_KEY',
    default='zGFEFZ7NvB4qWoZfs62EoDpzCjK3MV9cH7V4bJ0zP-E=',
    cast=str,
)


class SessionEncryptor:
    def __init__(self):
        self.fernet = Fernet(FERNET_KEY)

    def encrypt(self, data: dict) -> str:
        if not isinstance(data, dict):
            raise InvalidTokenException(
                'Only dicts can be encrypted', status_code=403
            )
        try:
            # dict -> str -> bytes -> str
            data: str = json.dumps(data)
            data: bytes = data.encode()
            data: bytes = self.fernet.encrypt(data=data)
            data: str = data.decode()
            return data
        except Exception as e:
            raise InvalidTokenException(repr(e), status_code=403)

    def decrypt(self, session: str) -> dict:
        if not isinstance(session, str):
            raise InvalidTokenException(
                'Only strings can be decrypted', status_code=403
            )
        try:
            # str -> bytes -> str -> dict
            data: bytes = self.fernet.decrypt(token=session)
            data: str = data.decode()
            data: dict = json.loads(data)
            return data
        except Exception as e:
            raise InvalidTokenException(repr(e), status_code=403)

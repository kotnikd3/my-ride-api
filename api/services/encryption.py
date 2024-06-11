import json

from cryptography.fernet import Fernet

from api.services.exceptions import InvalidTokenError


class SessionEncryptor:
    def __init__(self, fernet_key: str):
        self.fernet = Fernet(fernet_key)

    def encrypt(self, data: dict) -> str:
        if not isinstance(data, dict):
            raise InvalidTokenError('Only dicts can be encrypted')
        try:
            # dict -> str -> bytes -> str
            data: str = json.dumps(data)
            data: bytes = data.encode()
            data: bytes = self.fernet.encrypt(data=data)
            data: str = data.decode()
            return data
        except Exception as e:
            raise InvalidTokenError(e)

    def decrypt(self, session: str) -> dict:
        if not isinstance(session, str):
            raise InvalidTokenError('Only strings can be decrypted')
        try:
            # str -> bytes -> str -> dict
            data: bytes = self.fernet.decrypt(token=session)
            data: str = data.decode()
            data: dict = json.loads(data)
            return data
        except Exception as e:
            raise InvalidTokenError(e)

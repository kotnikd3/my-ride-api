import pytest

from api.services.encryption import SessionEncryptor
from api.services.exceptions import InvalidTokenException


def test_encrypt():
    session_encryptor = SessionEncryptor()

    encrypted_data = session_encryptor.encrypt(data={'foo': 'bar'})
    assert isinstance(encrypted_data, str)

    encrypted_data = session_encryptor.encrypt(data={})
    assert isinstance(encrypted_data, str)


def test_encrypt_returns_exception():
    session_encryptor = SessionEncryptor()

    with pytest.raises(InvalidTokenException) as context:
        session_encryptor.encrypt(data='NOT DICT')

    assert 'Only dicts can be encrypted' in str(context.value)


def test_decrypt():
    session_encryptor = SessionEncryptor()

    encrypted_data = session_encryptor.encrypt(data={'foo': 'bar'})
    decrypted_data = session_encryptor.decrypt(session=encrypted_data)

    assert isinstance(decrypted_data, dict)

    encrypted_data = session_encryptor.encrypt(data={})
    decrypted_data = session_encryptor.decrypt(session=encrypted_data)

    assert isinstance(decrypted_data, dict)


def test_decrypt_returns_exception():
    session_encryptor = SessionEncryptor()

    with pytest.raises(InvalidTokenException) as context:
        session_encryptor.decrypt(session={'foo': 'bar'})

    assert 'Only strings can be decrypted' in str(context.value)

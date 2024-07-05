from unittest import TestCase

from api.services.encryption import SessionEncryptor
from api.services.exceptions import InvalidTokenException


class TestSessionEncryptor(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.session_encryptor = SessionEncryptor()

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_encrypt(self):
        encrypted_data = self.session_encryptor.encrypt(data={'foo': 'bar'})
        self.assertIsInstance(encrypted_data, str)

        encrypted_data = self.session_encryptor.encrypt(data={})
        self.assertIsInstance(encrypted_data, str)

    def test_encrypt_returns_exception(self):
        with self.assertRaises(InvalidTokenException) as context:
            self.session_encryptor.encrypt(data='NOT DICT')

        self.assertIn('Only dicts can be encrypted', str(context.exception))

    def test_decrypt(self):
        encrypted_data = self.session_encryptor.encrypt(data={'foo': 'bar'})
        decrypted_data = self.session_encryptor.decrypt(session=encrypted_data)

        self.assertIsInstance(decrypted_data, dict)

        encrypted_data = self.session_encryptor.encrypt(data={})
        decrypted_data = self.session_encryptor.decrypt(session=encrypted_data)

        self.assertIsInstance(decrypted_data, dict)

    def test_decrypt_returns_exception(self):
        # Check if 'Expired' is in the exception message
        with self.assertRaises(InvalidTokenException) as context:
            self.session_encryptor.decrypt(session={'foo': 'bar'})

        self.assertIn('Only strings can be decrypted', str(context.exception))

from unittest import TestCase

from api.main import app


class TestController(TestCase):
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        self.client = app.test_client()

    def tearDown(self):
        self.ctx.pop()

    def test_index(self):
        response = self.client.get('/')
        self.assertIn('My ride', response.text)

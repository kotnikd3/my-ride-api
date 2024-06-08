import pytest

from api.infrastructure.controllers import app as application


@pytest.fixture()
def app():
    app = application

    app.config.update(
        {
            "TESTING": True,
        }
    )

    # other setup can go here
    yield app
    # clean up / reset resources here


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

"""Pytest configuration and fixtures."""

from contextlib import contextmanager
from dataclasses import dataclass
from itertools import count
from pathlib import Path
from random import randint

import httpx
import pytest
from serieux import Sources

from easy_oauth.testing.oauth_mock import app as oauth_app
from easy_oauth.testing.utils import create_endpoint

from .app import make_app

OAUTH_PORT = 29313
_port = count(OAUTH_PORT + randint(1, 1000))


here = Path(__file__).parent


@pytest.fixture(scope="session")
def oauth_endpoint():
    """
    Start the OAuth mock server in a background thread.

    Yields:
        str: The base URL of the mock OAuth server (e.g., "http://127.0.0.1:29313")
    """
    with create_endpoint(oauth_app, "127.0.0.1", OAUTH_PORT) as endpoint:
        yield endpoint


@pytest.fixture
def set_email(oauth_endpoint):
    def set_email(email):
        response = httpx.post(f"{oauth_endpoint}/set_email", data={"email": email})
        assert response.status_code == 200
        return email

    try:
        yield set_email
    finally:
        set_email("test@example.com")


@dataclass
class TokenInteractor:
    root: str
    email: str
    token: str

    @classmethod
    def make(cls, app, email):
        response = httpx.get(f"{app}/token", follow_redirects=True)
        assert response.status_code == 200
        token = response.json()["refresh_token"]
        return cls(app, email, token)

    def expect(self, response, expect=None):
        expect = 200 if expect is None else expect
        if response.status_code != expect:
            raise AssertionError(
                f"Expected status {expect}, got {response.status_code}: {response.text}"
            )
        return response

    def get(self, endpoint, expect=None, **data):
        response = httpx.get(
            f"{self.root}{endpoint}",
            headers={"Authorization": f"Bearer {self.token}"},
            params=data,
        )
        return self.expect(response, expect)

    def post(self, endpoint, expect=None, **data):
        response = httpx.post(
            f"{self.root}{endpoint}",
            headers={"Authorization": f"Bearer {self.token}"},
            json=data,
        )
        return self.expect(response, expect)


@pytest.fixture(scope="session")
def app(oauth_endpoint):
    port = next(_port)
    with create_endpoint(make_app(Path(here / "appconfig.yaml")), "127.0.0.1", port) as endpoint:
        yield endpoint


@pytest.fixture
def user(app, set_email):
    def make_interactor(email):
        set_email(email)
        return TokenInteractor.make(app, email)

    yield make_interactor


@pytest.fixture
def app_write(tmpdir, oauth_endpoint):
    port = next(_port)
    with create_endpoint(
        make_app(Path(here / "appconfig.yaml"), tmpdir), "127.0.0.1", port
    ) as endpoint:
        yield endpoint


@pytest.fixture
def user_write(app_write, set_email):
    def make_interactor(email):
        set_email(email)
        return TokenInteractor.make(app_write, email)

    yield make_interactor


@pytest.fixture
def app_force_user(tmpdir):
    @contextmanager
    def make(email):
        port = next(_port)
        sources = Sources(Path(here / "noauthconfig.yaml"), {"force_user": {"email": email}})
        with create_endpoint(make_app(sources, tmpdir), "127.0.0.1", port) as endpoint:
            yield endpoint

    yield make

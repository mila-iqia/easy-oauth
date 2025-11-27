"""Pytest configuration and fixtures."""

from contextlib import contextmanager
from pathlib import Path

import pytest
from serieux import Sources

from easy_oauth.testing.utils import AppTester, OAuthMock

from .app import make_app

OAUTH_PORT = 29313

here = Path(__file__).parent


@pytest.fixture(scope="session")
def oauth_mock():
    with OAuthMock(port=OAUTH_PORT) as oauth:
        yield oauth


@pytest.fixture(scope="session")
def app(oauth_mock):
    app = make_app(Path(here / "appconfig.yaml"))
    with AppTester(app, oauth_mock) as appt:
        yield appt


@pytest.fixture
def app_write(tmpdir, oauth_mock):
    app = make_app(Path(here / "appconfig.yaml"), tmpdir)
    with AppTester(app, oauth_mock) as appt:
        yield appt


@pytest.fixture
def app_prefix(tmpdir, oauth_mock):
    app = make_app(Path(here / "prefixconfig.yaml"), tmpdir)
    with AppTester(app, oauth_mock) as appt:
        yield appt


@pytest.fixture
def app_force_user(tmpdir, oauth_mock):
    @contextmanager
    def make(email):
        sources = Sources(Path(here / "noauthconfig.yaml"), {"force_user": {"email": email}})
        app = make_app(sources, tmpdir)
        with AppTester(app, oauth_mock) as appt:
            yield appt.base_url

    yield make


@pytest.fixture
def app_default_caps(tmpdir, oauth_mock):
    app = make_app(Path(here / "defaultcaps.yaml"), tmpdir)
    with AppTester(app, oauth_mock) as appt:
        yield appt

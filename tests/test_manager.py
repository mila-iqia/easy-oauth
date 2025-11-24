import httpx
import pytest


def test_oauth_flow(oauth_endpoint):
    response = httpx.post(
        f"{oauth_endpoint}/oauth2/token",
        data={"grant_type": "authorization_code", "code": "test"},
    )
    assert response.status_code == 200


def test_hello_nologin(app):
    with httpx.Client() as client:
        response = client.get(f"{app}/hello")
        assert response.text == "Hello, None!"
        assert response.status_code == 200


def test_hello_login(app):
    with httpx.Client() as client:
        client.get(f"{app}/login", follow_redirects=True)
        response = client.get(f"{app}/hello")
        assert response.text == "Hello, test@example.com!"
        assert response.status_code == 200


def test_hello_ensure(app):
    with httpx.Client() as client:
        response = client.get(f"{app}/hello_ensure", follow_redirects=True)
        assert response.text == "Hello, test@example.com!"
        assert response.status_code == 200


def test_hello_token(app):
    response = httpx.get(f"{app}/token", follow_redirects=True)
    token = response.json()["refresh_token"]
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.text == "Hello, test@example.com!"
    assert response.status_code == 200


@pytest.mark.parametrize(
    "email,expected_status",
    [
        ("boss@corleone.com", 200),
        ("paul.baguette@corleone.com", 200),
        ("hubert.bonjour@courrier-chaud.fr", 403),
        ("wiggum@springfield.us", 403),
        ("admin@admin.admin", 200),
    ],
)
def test_capability_restriction(user, email, expected_status):
    u = user(email)
    targ = "Little Jimmy"
    response = u.get("/murder", target=targ, expect=expected_status)
    if expected_status == 200:
        assert response.text == f"{targ} was murdered by {u.email}"


@pytest.mark.parametrize(
    "email,expected_status",
    [
        ("boss@corleone.com", 403),
        ("paul.baguette@corleone.com", 403),
        ("hubert.bonjour@courrier-chaud.fr", 403),
        ("wiggum@springfield.us", 403),
        ("admin@admin.admin", 200),
    ],
)
def test_capability_admin(user, email, expected_status):
    u = user(email)
    response = u.get("/god", expect=expected_status)
    if expected_status == 200:
        assert response.text == f"{u.email} is god"

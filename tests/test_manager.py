from pathlib import Path

import httpx
import pytest
from serieux import deserialize


class D(dict):
    def __getattr__(self, attr):
        return self.get(attr, None)


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


def test_logout(app):
    with httpx.Client() as client:
        client.get(f"{app}/login", follow_redirects=True)
        assert client.get(f"{app}/hello").text == "Hello, test@example.com!"
        client.get(f"{app}/logout")
        assert client.get(f"{app}/hello").text == "Hello, None!"


def test_hello_ensure(app):
    with httpx.Client() as client:
        response = client.get(f"{app}/hello_ensure", follow_redirects=True)
        assert response.text == "Hello, test@example.com!"
        assert response.status_code == 200


def test_bake_ensure(app, set_email):
    set_email("paul.baguette@corleone.com")
    with httpx.Client() as client:
        response = client.get(f"{app}/bake", params={"food": "potato"}, follow_redirects=True)
        assert response.text == "potato was baked by paul.baguette@corleone.com"
        assert response.status_code == 200


def test_hello_token(app):
    response = httpx.get(f"{app}/token", follow_redirects=True)
    token = response.json()["refresh_token"]
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.text == "Hello, test@example.com!"
    assert response.status_code == 200


def test_hello_token_renew(app, freezer):
    response = httpx.get(f"{app}/token", follow_redirects=True)
    token = response.json()["refresh_token"]
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.text == "Hello, test@example.com!"
    assert response.status_code == 200
    freezer.tick(delta=86_400)
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.text == "Hello, test@example.com!"
    assert response.status_code == 200


def queries(*queries):
    return pytest.mark.parametrize("query", queries)


@queries(
    D(user="boss@corleone.com"),
    D(user="paul.baguette@corleone.com"),
    D(user="hubert.bonjour@courrier-chaud.fr", status=403),
    D(user="wiggum@springfield.us", status=403),
    D(user="admin@admin.admin"),
)
def test_capability_restriction(user, query):
    u = user(query.user)
    targ = "Little Jimmy"
    response = u.get("/murder", target=targ, expect=query.status)
    if query.status is None:
        assert response.text == f"{targ} was murdered by {u.email}"


def test_no_capability(app):
    response = httpx.get(f"{app}/murder", params={"target": "nobody"})
    assert response.status_code == 401


@queries(
    D(user="boss@corleone.com", status=403),
    D(user="paul.baguette@corleone.com", status=403),
    D(user="hubert.bonjour@courrier-chaud.fr", status=403),
    D(user="wiggum@springfield.us", status=403),
    D(user="admin@admin.admin"),
)
def test_capability_admin(user, query):
    u = user(query.user)
    response = u.get("/god", expect=query.status)
    if query.status is None:
        assert response.text == f"{u.email} is god"


@queries(
    # Trying to view own capabilities
    D(user="boss@corleone.com", caps={"mafia"}),
    D(user="paul.baguette@corleone.com", caps={"mafia", "baker"}),
    D(user="hubert.bonjour@courrier-chaud.fr", caps={"villager"}),
    D(user="wiggum@springfield.us", caps={"police"}),
    D(user="admin@admin.admin", caps={"admin"}),
    # Trying to view someone else's capabilities
    D(user="boss@corleone.com", email="hubert.bonjour@courrier-chaud.fr", status=403),
    D(user="admin@admin.admin", email="hubert.bonjour@courrier-chaud.fr", caps={"villager"}),
)
def test_manage_list(user, query):
    u = user(query.user)
    email = query.email or query.user
    response = u.get("/manage_capabilities/list", email=email, expect=query.status)
    if query.status is None:
        assert response.json()["email"] == email
        assert set(response.json()["capabilities"]) == query.caps


@queries(
    D(user="boss@corleone.com", status=403),
    D(user="paul.baguette@corleone.com", status=403),
    D(user="hubert.bonjour@courrier-chaud.fr", status=403),
    D(user="wiggum@springfield.us", status=403),
    D(user="admin@admin.admin", email="hubert.bonjour@courrier-chaud.fr"),
)
def test_cannot_manage_users(user_write, query):
    u = user_write(query.user)
    target = query.email or u.email
    u.post("/manage_capabilities/add", email=target, capability="baker", expect=query.status)
    u.post("/manage_capabilities/remove", email=target, capability="baker", expect=query.status)
    u.post("/manage_capabilities/set", email=target, capabilities=["baker"], expect=query.status)


def test_add_capability(user_write, tmpdir):
    u = user_write("wiggum@springfield.us")
    admin = user_write("admin@admin.admin")

    targ = "Homer"
    u.get("/murder", target=targ, expect=403)

    admin.post("/manage_capabilities/add", email=u.email, capability="mafia")

    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == {"police", "mafia"}


def test_remove_capability(user_write, tmpdir):
    u = user_write("boss@corleone.com")
    admin = user_write("admin@admin.admin")

    targ = "Homer"
    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    admin.post("/manage_capabilities/remove", email=u.email, capability="mafia")
    u.get("/murder", target=targ, expect=403)

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == set()


def test_set_capability(user_write, tmpdir):
    u = user_write("boss@corleone.com")
    admin = user_write("admin@admin.admin")

    targ = "Homer"
    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    admin.post("/manage_capabilities/set", email=u.email, capabilities=["baker"])

    u.get("/murder", target=targ, expect=403)
    assert u.get("/bake", food="lemon pie").text == f"lemon pie was baked by {u.email}"

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == {"baker"}

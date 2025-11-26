from pathlib import Path

import httpx
import pytest
from serieux import deserialize

from easy_oauth.manager import OAuthManager

here = Path(__file__).parent


class D(dict):
    def __getattr__(self, attr):
        return self.get(attr, None)


def test_oauth_flow(oauth_mock):
    response = httpx.post(
        f"{oauth_mock.base_url}/oauth2/token",
        data={"grant_type": "authorization_code", "code": "test"},
    )
    assert response.status_code == 200


def test_hello_nologin(app):
    with httpx.Client() as client:
        response = client.get(f"{app}/hello")
        assert response.text == "Hello, None!"
        assert response.status_code == 200


def test_hello_login(app):
    app.set_email("test@example.com")
    with httpx.Client() as client:
        client.get(f"{app}/login", follow_redirects=True)
        response = client.get(f"{app}/hello")
        assert response.text == "Hello, test@example.com!"
        assert response.status_code == 200


def test_logout(app):
    app.set_email("test@example.com")
    with httpx.Client() as client:
        client.get(f"{app}/login", follow_redirects=True)
        assert client.get(f"{app}/hello").text == "Hello, test@example.com!"
        client.get(f"{app}/logout")
        assert client.get(f"{app}/hello").text == "Hello, None!"


def test_hello_ensure(app):
    app.set_email("test@example.com")
    with httpx.Client() as client:
        response = client.get(f"{app}/hello_ensure", follow_redirects=True)
        assert response.text == "Hello, test@example.com!"
        assert response.status_code == 200


def test_bake_ensure(app):
    app.set_email("paul.baguette@corleone.com")
    with httpx.Client() as client:
        response = client.get(f"{app}/bake", params={"food": "potato"}, follow_redirects=True)
        assert response.text == "potato was baked by paul.baguette@corleone.com"
        assert response.status_code == 200


def test_hello_token(app):
    app.set_email("test@example.com")
    response = httpx.get(f"{app}/token", follow_redirects=True)
    token = response.json()["refresh_token"]
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.text == "Hello, test@example.com!"
    assert response.status_code == 200


def test_hello_bad_token(app):
    response = httpx.get(f"{app}/hello", headers={"Authorization": "Bearer XXX"})
    assert response.status_code in (401, 500)

    oauth = deserialize(OAuthManager, Path(here / "appconfig.yaml"))
    token = oauth.secrets_serializer.dumps("XXX")
    response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code in (401, 500)


def test_hello_token_renew(app, freezer):
    app.set_email("test@example.com")
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
def test_capability_restriction(app, query):
    u = app.client(query.user)
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
    D(user="mega-admin@admin.admin"),
)
def test_capability_admin(app, query):
    u = app.client(query.user)
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
def test_manage_list(app, query):
    u = app.client(query.user)
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
def test_cannot_manage_users(app_write, query):
    u = app_write.client(query.user)
    target = query.email or u.email
    u.post("/manage_capabilities/add", email=target, capability="baker", expect=query.status)
    u.post("/manage_capabilities/remove", email=target, capability="baker", expect=query.status)
    u.post("/manage_capabilities/set", email=target, capabilities=["baker"], expect=query.status)


def test_add_capability(app_write, tmpdir):
    u = app_write.client("wiggum@springfield.us")
    admin = app_write.client("admin@admin.admin")

    targ = "Homer"
    u.get("/murder", target=targ, expect=403)

    admin.post("/manage_capabilities/add", email=u.email, capability="mafia")

    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == {"police", "mafia"}


def test_remove_capability(app_write, tmpdir):
    u = app_write.client("boss@corleone.com")
    admin = app_write.client("admin@admin.admin")

    targ = "Homer"
    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    admin.post("/manage_capabilities/remove", email=u.email, capability="mafia")
    u.get("/murder", target=targ, expect=403)

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == set()


def test_admin_override_persists(app_write, tmpdir):
    """
    Removing the 'admin' capability from mega-admin@admin.admin
    should not make them lose 'admin', since it is an override in appconfig.yaml.
    """
    u = app_write.client("mega-admin@admin.admin")
    admin = app_write.client("admin@admin.admin")

    # Sanity: mega-admin can perform admin-only action
    response = u.get("/god")
    assert response.status_code == 200
    assert response.text == f"{u.email} is god"

    # Remove admin explicitly in assigned capabilities (file-backed)
    admin.post("/manage_capabilities/remove", email=u.email, capability="admin")

    # Still must have admin cap due to override, can still perform admin action
    response2 = u.get("/god")
    assert response2.status_code == 200
    assert response2.text == f"{u.email} is god"

    # In fact, the capabilities file must NOT contain "admin" for mega-admin@admin.admin,
    # but the API should still report it as an effective capability
    caps_file = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert "admin" not in caps_file.get(u.email, set())


def test_set_capability(app_write, tmpdir):
    u = app_write.client("boss@corleone.com")
    admin = app_write.client("admin@admin.admin")

    targ = "Homer"
    response = u.get("/murder", target=targ)
    assert response.text == f"{targ} was murdered by {u.email}"

    admin.post("/manage_capabilities/set", email=u.email, capabilities=["baker"])

    u.get("/murder", target=targ, expect=403)
    assert u.get("/bake", food="lemon pie").text == f"lemon pie was baked by {u.email}"

    new_caps = deserialize(dict[str, set[str]], Path(tmpdir / "caps.yaml"))
    assert new_caps[u.email] == {"baker"}


def test_force_admin(app_force_user):
    with app_force_user("admin@admin.admin") as app:
        resp = httpx.get(f"{app}/hello")
        assert resp.status_code == 200
        assert resp.text == "Hello, admin@admin.admin!"

        resp = httpx.get(f"{app}/murder", params={"target": "Bart"})
        assert resp.status_code == 200
        assert resp.text == "Bart was murdered by admin@admin.admin"

        resp = httpx.get(f"{app}/bake", params={"food": "chocolate cake"})
        assert resp.status_code == 200
        assert resp.text == "chocolate cake was baked by admin@admin.admin"


def test_force_cap(app_force_user):
    with app_force_user("boss@corleone.com") as app:
        resp = httpx.get(f"{app}/hello")
        assert resp.status_code == 200
        assert resp.text == "Hello, boss@corleone.com!"

        resp = httpx.get(f"{app}/murder", params={"target": "Lisa"})
        assert resp.status_code == 200
        assert resp.text == "Lisa was murdered by boss@corleone.com"

        resp = httpx.get(f"{app}/bake", params={"food": "baguette"})
        assert resp.status_code == 403  # boss does not have baker capability


def test_force_user_token(app_force_user):
    # Make sure the token flow is still valid
    with app_force_user("admin@admin.admin") as app:
        response = httpx.get(f"{app}/token", follow_redirects=True)
        token = response.json()["refresh_token"]
        assert token == "XXX"
        response = httpx.get(f"{app}/hello", headers={"Authorization": f"Bearer {token}"})
        assert response.text == "Hello, admin@admin.admin!"
        assert response.status_code == 200


# easy-oauth

Small package to add OAuth-based authentication to a Starlette/FastAPI app. Users may also retrieve a token to authenticate themselves.


## Install

`uv add git+https://github.com/mila-iqia/easy-oauth@v0.0.1`


## Usage

If you want to authenticate through Google, first you will need to create a project in GCP and get a client_id and client_secret from the console. Then you can do it like this:


```python
from easy_oauth import OAuthManager, CapabilitySet

oauth = OAuthManager(
    # This page describes where the endpoint urls are defined
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    # A secret key to encrypt the session and tokens, you can generate it yourself
    secret_key=SECRET_KEY,
    # The client id from Google Console
    client_id=CLIENT_ID,
    # The client secret from Google Console
    client_secret=CLIENT_SECRET,
    # Arguments to the auth request, you can just use what's below
    client_kwargs={
        "scope": "openid email",
        "prompt": "select_account",
    }
    # Set of capabilities that can be assigned to users
    capabilities=CapabilitySet(
        graph={
            # Basic capability
            "read": [],
            # write, also implies read
            "write": ["read"],
            # moderate, also implies read and write
            "moderate": ["read", "write"],
            # announce, also implies read and write
            "announce": ["read", "write"],
            # "user_management" is the capability needed to set the capabilities of
            # users.
            "user_management": [],
        },
        # Create the "admin" capability that has every other capability
        auto_admin=True,
        # File where each user's capability is stored
        user_file="caps.yaml",
    ),
    # If you want routes to be at /api/v1/login etc., put "/api/v1" here
    prefix="",
)

app = FastAPI()

oauth.install(app)
```

Here is an example of a user capability file:

```yaml
your-email@you.com:
  - admin
friend@rainbows.com:
  - moderate
  - announce
pierre-jean-jacques@youhou.fr:
  - read
hateful-being@cornhole.co: []
```

In order to require a certain capability for a given route, you can declare it like this in FastAPI:

```python
@app.get("/shout")
async def route_shout(
    request: Request,
    message: str,
    email: str = Depends(oauth.get_email_capability("announce", redirect=True)),
):
    return PlainTextResponse(f"{email} shouts {message!r}")
```

If `redirect=True` in `get_email_capability`, then the browser will redirect to the login page if the user is not logged in, then it will redirect back to the original page.


### Token workflow

First, the user should point their browser to the `/token` endpoint. This will prompt them to log in and it will display a token. Copy it.

Then you can use use Bearer authentication with the token. That is to say, the `Authorization` header should be set to `Bearer INSERT_TOKEN_HERE`. Using `httpx`, for example (it should work the same with `requests`):

```python
# Unauthorized access
assert httpx.get(f"{app_url}/something").status_code == 401

# Authorized access
assert httpx.get(f"{app_url}/something", headers={"Authorization": f"Bearer {token}"}).status_code == 200
```


### Reading configuration from a file

The configuration for the above OAuthManager can be written in a file, like this:

```yaml
server_metadata_url: https://accounts.google.com/.well-known/openid-configuration
secret_key: "<SECRET_KEY>"
client_id: "<CLIENT_ID>"
client_secret: "<CLIENT_SECRET>"
client_kwargs:
  scope: openid email
  prompt: select_account
capabilities:
  graph:
    read: []
    write: [read]
    moderate: [read, write]
    announce: [read, write]
    user_management: []
  auto_admin: true
  user_file: caps.yaml
prefix: ""
```

And instantiated like this:

```python
from serieux import deserialize

oauth = deserialize(OAuthManager, Path("config.yaml"))
```

Of course, you can nest that configuration within a larger configuration.


### Encrypting the configuration

The secrets written in the config file can be encrypted using `serieux` (The `-m` option must point to the type of the root of the configuration using the syntax `module:symbol`, in this case it is simply `easy_oauth:OAuthManager`):

```bash
export SERIEUX_PASSWORD="change_me!!1"
serieux patch -m easy_oauth:OAuthManager -f config.yaml
```

You must then modify the instantiation code like this:

```python
import os
from serieux import deserialize
from serieux.features.encrypt import EncryptionKey

oauth = deserialize(OAuthManager, Path("config.yaml"), EncryptionKey(os.getenv("SERIEUX_PASSWORD")))
```

## Routes

The OAuthManager automatically adds the following routes when installed on your Starlette/FastAPI application:

### Authentication Routes

- **GET `/login`**
  - Initiates the OAuth login flow
  - Clears the current session and redirects to the OAuth provider
  - Query parameters:
    - `redirect` (optional): Name of the auth callback route (default: `auth`)
    - `offline_token=true` (optional): Request a refresh token with offline access
  - Stores the original URL in session to redirect back after authentication

- **GET `/auth`**
  - OAuth callback route that handles the authorization code
  - Exchanges the authorization code for tokens and stores user information in the session
  - Redirects to the original URL (default: `/`)

- **GET `/token`**
  - Returns an encrypted refresh token for the authenticated user
  - Response: `{"refresh_token": "<encrypted_token>"}`

- **GET `/logout`**
  - Clears the user session and redirects to `/`

### Capability Management Routes

- **GET `/manage_capabilities/list`**
  - Lists capabilities for a user
  - Query parameters:
    - `email` (optional): Email address to query (defaults to current user)
  - Requires user management capability if querying another user's capabilities
  - Response: `{"status": "ok", "email": "<email>", "capabilities": [...]}`

The following routes are only added if there is a `user_management` capability:

- **POST `/manage_capabilities/add`**
  - Adds a capability to a user
  - Requires user management capability
  - Request body: `{"email": "<email>", "capability": "<capability_name>"}`
  - Response: `{"status": "ok", "email": "<email>", "capabilities": [...]}`

- **POST `/manage_capabilities/remove`**
  - Removes a capability from a user
  - Requires user management capability
  - Request body: `{"email": "<email>", "capability": "<capability_name>"}`
  - Response: `{"status": "ok", "email": "<email>", "capabilities": [...]}`

- **POST `/manage_capabilities/set`**
  - Sets the complete capability set for a user (replaces existing capabilities)
  - Requires user management capability
  - Request body: `{"email": "<email>", "capabilities": ["<cap1>", "<cap2>", ...]}`
  - Response: `{"status": "ok", "email": "<email>", "capabilities": [...]}`


## Testing

For testing, easy_oauth defines a mock OAuth server that always logs you in unconditionally as `test@example.com` by default. That way you don't need a browser or any secrets to test things.

```bash
uvicorn easy_oauth.testing.oauth_mock:app
```

To set the email address the mock OAuth server with authentify all requests as, send a POST request with JSON data like this:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "a@b.c"}' http://127.0.0.1:8000/set_email
```

To use it with easy_oauth, set `server_metadata_url` to `http://127.0.0.1:8000/.well-known/openid-configuration` (depending on the host and port).


### Fixtures

easy-oauth provides the `OAuthMock` and `AppTester` classes to make testing easier. Here is a very simple example of how to use them:


```python
from easy_oauth.testing.utils import AppTester, OAuthMock

@pytest.fixture(scope="session")
def oauth_mock():
    # Start one mock oauth server for the session. It's important that the
    # OAUTH_PORT conforms to the server_metadata_url you configure the test app
    # with
    with OAuthMock(port=OAUTH_PORT) as oauth:
        yield oauth

@pytest.fixture(scope="session")
def app(oauth_mock):
    # This doesn't have to be session-scoped, but if your app is read-only it may
    # as well be.
    with AppTester(your_app, oauth_mock) as appt:
        yield appt

def test_view_payroll(app):
    # Use app.client to pretend to be various users
    guest = app.client()
    user = app.client("simple.user@website.web")
    accountant = app.client("mr.bean@website.web")
    admin = app.client("admin@website.web")

    # Guests are not authentified (so we expect HTTP error 401)
    guest.get("/payroll/view", expect=401)
    # Normal users are unauthorized to view the payroll
    user.get("/payroll/view", expect=403)
    # Accountants and admins are authorized
    accountant.get("/payroll/view", expect=200)
    admin.get("/payroll/view", expect=200)
```


## TODO

There are a few things that need to be done in the future:

* Add an endpoint to revoke tokens.
* Users with `user_management` capability should only be able to add/remove capabilities that they have.
* API tokens associated to capabilities but not accounts

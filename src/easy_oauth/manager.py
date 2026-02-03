import asyncio
import secrets
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import cached_property, lru_cache

import httpx
from authlib.integrations.starlette_client import OAuth
from authlib.jose import JoseError, JWTClaims, jwt
from itsdangerous import BadData, URLSafeSerializer
from serieux import deserialize, serialize
from serieux.features.encrypt import Secret
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse

from .cap import CapabilitySet
from .structs import OpenIDConfiguration, Payload, UserInfo


@lru_cache(maxsize=100)
def _headless_store(session_token: str) -> dict[str, asyncio.Event | list[str]]:
    assert session_token

    return {"event": asyncio.Event(), "token": []}


@dataclass(kw_only=True)
class OAuthManager:
    server_metadata_url: str
    client_kwargs: dict[str, str] = field(default_factory=dict)
    secret_key: Secret[str] = field(default_factory=lambda: secrets.token_urlsafe(32))
    client_id: Secret[str] = None
    client_secret: Secret[str] = None
    force_user: UserInfo = None
    capabilities: CapabilitySet = field(default_factory=lambda: CapabilitySet({}))
    prefix: str = ""

    # [serieux: ignore]
    token_cache: dict = field(default_factory=dict)

    def __post_init__(self):
        self.user_management_capability = self.capabilities.registry.registry.get(
            "user_management", None
        )

    @cached_property
    def server_metadata(self):
        return deserialize(OpenIDConfiguration, self.server_metadata_url)

    @cached_property
    def secrets_serializer(self):
        return URLSafeSerializer(self.secret_key)

    ###########
    # Helpers #
    ###########

    def ensure_user_manager(self, email):
        if self.user_management_capability is None or not self.capabilities.check(
            email, self.user_management_capability
        ):
            raise HTTPException(
                status_code=403,
                detail=f"{self.user_management_capability} capability is required",
            )

    async def get_user(self, request: Request):
        if self.force_user:
            return serialize(UserInfo, self.force_user)
        if auth := request.headers.get("Authorization"):
            match auth.split("Bearer "):
                case ("", rtoken):
                    try:
                        rtoken = self.secrets_serializer.loads(rtoken)
                    except BadData:
                        raise HTTPException(status_code=401, detail="Malformed authorization")
                    if user := await self.user_from_refresh_token(rtoken):
                        user = serialize(UserInfo, user)
                        request.session["user"] = user
                        return user
                    else:  # pragma: no cover
                        raise HTTPException(status_code=401, detail="Invalid user")
                case _:  # pragma: no cover
                    raise HTTPException(status_code=401, detail="Malformed authorization")
        return request.session.get("user")

    async def get_email(self, request: Request):
        user = await self.get_user(request)
        return user["email"] if user is not None else user

    async def ensure_email(self, request: Request):
        user = await self.get_user(request)
        if user is None:
            request.session["redirect_after_login"] = str(request.url)
            raise HTTPException(
                status_code=307,
                headers={"Location": str(request.url_for("login"))},
            )
        else:
            return user["email"]

    def get_email_capability(self, cap=None, redirect=False):
        if isinstance(cap, str):
            cap = deserialize(self.capabilities.captype, cap)

        async def get(request: Request):
            if redirect:
                email = await self.ensure_email(request)
            else:
                email = await self.get_email(request)
            if cap is None or self.capabilities.check(email, cap):
                yield email
            elif email is None:
                raise HTTPException(status_code=401, detail="Authentication required")
            else:
                raise HTTPException(status_code=403, detail=f"{cap} capability required")

        return get

    async def user_from_refresh_token(self, rtoken):
        match self.token_cache.get(rtoken, None):
            case (user, _, expiry) if expiry < datetime.now():
                return await self.refresh_token(rtoken)
            case (user, _, expiry):
                return user
            case None:
                return await self.refresh_token(rtoken)

    async def refresh_token(self, rtoken):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": rtoken,
            "grant_type": "refresh_token",
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(self.server_metadata.token_endpoint, data=data)
            response.raise_for_status()
            data = response.json()
            atoken = data.get("access_token")
            user = deserialize(UserInfo, data.get("id_token"))
            expiry = datetime.now() + timedelta(seconds=data.get("expires_in", 3600))
            self.token_cache[rtoken] = (user, atoken, expiry)
            return user

    async def assimilate_payload(self, request):
        token = await self.oauth.authorize_access_token(request)
        payload = deserialize(Payload, token)

        if payload.userinfo:
            request.session["user"] = serialize(UserInfo, payload.userinfo)
            request.session["access_token"] = payload.access_token
            request.session["refresh_token"] = payload.refresh_token

    def _init_headless(self, request: Request):
        """Detect and initialize headless session."""
        headless = request.query_params.get("headless", "false").lower() == "true"

        if headless_session := request.query_params.get("headless_session", None):
            try:
                decoded: JWTClaims = jwt.decode(headless_session, key=self.secret_key)
                decoded.validate()
                request.session["headless_session"] = decoded["session"]
            except JoseError:
                request.session["headless_session"] = None

        return headless

    ##########
    # Routes #
    ##########

    async def route_login(self, request: Request):
        red = request.session.get("redirect_after_login", "/")
        request.session.clear()

        request.session["redirect_after_login"] = red
        if self.force_user:  # pragma: no cover
            # Pages won't redirect to /login when force_user is True,
            # so this won't happen unless the user directly goes to /login
            return RedirectResponse(url=red)

        if self._init_headless(request):
            headless_session = request.session.get(
                "headless_session",
                jwt.encode(
                    {"alg": "HS256"},
                    payload={
                        "session": secrets.token_urlsafe(32),
                        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
                    },
                    key=self.secret_key,
                ),
            )
            login_params = urllib.parse.urlencode(
                {"headless_session": headless_session, "headless": False}
            )
            token_params = urllib.parse.urlencode(
                {"headless_session": headless_session, "headless": True}
            )
            return JSONResponse(
                {
                    "login_url": f"{request.url_for('token')}?{login_params}",
                    "token_url": f"{request.url_for('token')}?{token_params}",
                }
            )

        auth_route = request.query_params.get("redirect", "auth")
        redirect_uri = request.url_for(auth_route)
        params = {}
        if request.query_params.get("offline_token") == "true":
            params = {"access_type": "offline", "prompt": "consent"}
        return await self.oauth.authorize_redirect(
            request,
            str(redirect_uri),
            **params,
        )

    async def route_auth(self, request):
        if not self.force_user:
            await self.assimilate_payload(request)
        red = request.session.get("redirect_after_login", "/")
        return RedirectResponse(url=red)

    async def route_token(self, request: Request):
        if self.force_user:
            return JSONResponse({"refresh_token": "XXX"})

        headless = self._init_headless(request)
        headless_session = request.session.get("headless_session", None)

        if headless and headless_session:
            headless_state = _headless_store(headless_session)
            await headless_state["event"].wait()
            try:
                return JSONResponse({"refresh_token": headless_state["token"].pop()})
            except IndexError:
                # The token has been used, a new one will need to be generated
                return PlainTextResponse("Unauthorized", status_code=401)

        if state := request.query_params.get("state"):
            await self.assimilate_payload(request)

        if not (rt := request.session.get("refresh_token")):
            if not state:
                login_url = request.url_for("login")
                params: dict = {
                    **request.query_params,
                    "offline_token": "true",
                    "redirect": "token",
                }
                params.pop("state", None)
                return RedirectResponse(url=f"{login_url}?{urllib.parse.urlencode(params)}")
            else:  # pragma: no cover
                return PlainTextResponse("Unauthorized", status_code=401)

        ert = self.secrets_serializer.dumps(rt)

        if headless_session:
            headless_state = _headless_store(headless_session)
            headless_state["token"].insert(0, ert)
            headless_state["event"].set()

        return JSONResponse({"refresh_token": ert})

    async def route_logout(self, request):
        request.session.clear()
        return RedirectResponse(url="/")

    ##########################
    # User management routes #
    ##########################

    def _get_user_capabilities(self, email):
        db = self.capabilities.db
        return serialize(set[self.capabilities.captype], db.value.get(email, set()))

    def _manage_cap_response(self, email):
        return JSONResponse(
            {
                "status": "ok",
                "email": email,
                "capabilities": self._get_user_capabilities(email),
            }
        )

    async def _manage_generic(self, request, reqcls):
        user = await self.get_email(request)
        self.ensure_user_manager(user)

        req = deserialize(reqcls, await request.json())

        db = self.capabilities.db
        req.apply(db.value)
        db.save()

        return self._manage_cap_response(req.email)

    async def route_manage_capabilities_add(self, request):
        @dataclass
        class AddRequest:
            email: str
            capability: self.capabilities.captype

            def apply(self, caps):
                caps.setdefault(self.email, set()).add(self.capability)

        return await self._manage_generic(request, AddRequest)

    async def route_manage_capabilities_remove(self, request):
        @dataclass
        class RemoveRequest:
            email: str
            capability: self.capabilities.captype

            def apply(self, caps):
                caps.setdefault(self.email, set()).discard(self.capability)

        return await self._manage_generic(request, RemoveRequest)

    async def route_manage_capabilities_set(self, request):
        @dataclass
        class SetRequest:
            email: str
            capabilities: set[self.capabilities.captype]

            def apply(self, caps):
                caps[self.email] = self.capabilities

        return await self._manage_generic(request, SetRequest)

    async def route_manage_capabilities_list_user(self, request):
        user = await self.get_email(request)

        @dataclass
        class ListRequest:
            email: str = user

        req = deserialize(ListRequest, dict(request.query_params))

        if req.email != user:
            self.ensure_user_manager(user)

        return self._manage_cap_response(req.email)

    async def route_manage_capabilities_list(self, request: Request):
        user = await self.get_email(request)
        self.ensure_user_manager(user)

        users_capabilities = {}
        for email in self.capabilities.db.value.keys():
            users_capabilities[email] = self._get_user_capabilities(email)

        graph = self.capabilities.graph.copy()
        if self.capabilities.auto_admin:
            graph.setdefault("admin", list(graph.keys()))

        return JSONResponse({"status": "ok", "users": users_capabilities, "graph": graph})

    ##################
    # Install to app #
    ##################

    def install(self, app):
        app.add_middleware(
            SessionMiddleware,
            secret_key=self.secret_key,
            max_age=14 * 24 * 60 * 60,
        )

        oauth = OAuth()
        oauth.register(
            name="easy-oauth",
            client_id=self.client_id,
            client_secret=self.client_secret,
            server_metadata_url=self.server_metadata_url,
            client_kwargs=self.client_kwargs,
        )
        self.oauth = getattr(oauth, "easy-oauth")

        app.add_route(f"{self.prefix}/login", self.route_login, name="login")
        app.add_route(f"{self.prefix}/logout", self.route_logout)
        app.add_route(f"{self.prefix}/auth", self.route_auth, name="auth")
        app.add_route(f"{self.prefix}/token", self.route_token, name="token")

        if self.user_management_capability:
            app.add_route(
                f"{self.prefix}/manage_capabilities/add",
                self.route_manage_capabilities_add,
                methods=["POST"],
            )
            app.add_route(
                f"{self.prefix}/manage_capabilities/remove",
                self.route_manage_capabilities_remove,
                methods=["POST"],
            )
            app.add_route(
                f"{self.prefix}/manage_capabilities/set",
                self.route_manage_capabilities_set,
                methods=["POST"],
            )

        app.add_route(
            f"{self.prefix}/manage_capabilities/list_user",
            self.route_manage_capabilities_list_user,
        )
        app.add_route(
            f"{self.prefix}/manage_capabilities/list",
            self.route_manage_capabilities_list,
        )

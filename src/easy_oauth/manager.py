import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cached_property
from pathlib import Path

import httpx
from authlib.integrations.starlette_client import OAuth
from itsdangerous import URLSafeSerializer
from serieux import deserialize, serialize
from serieux.features.encrypt import Secret
from serieux.features.filebacked import DefaultFactory, FileBacked
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse

from .cap import Capability, CapabilitySet
from .structs import OpenIDConfiguration, Payload, UserInfo


@dataclass(kw_only=True)
class OAuthManager:
    server_metadata_url: str
    client_kwargs: dict[str, str]
    secret_key: Secret[str] = field(default_factory=lambda: secrets.token_urlsafe(32))
    client_id: Secret[str] = None
    client_secret: Secret[str] = None
    enable: bool = True
    capability_file: Path = None
    capset: CapabilitySet = field(default_factory=lambda: CapabilitySet({}))

    # [serieux: ignore]
    server_metadata: OpenIDConfiguration = None

    # [serieux: ignore]
    token_cache: dict = field(default_factory=dict)

    def __post_init__(self):
        self.server_metadata = deserialize(OpenIDConfiguration, self.server_metadata_url)
        self.secrets_serializer = URLSafeSerializer(self.secret_key)
        self.user_management_capability = self.capset.registry.registry.get(
            "user_management", None
        )

    @cached_property
    def capability_db(self):
        return deserialize(
            FileBacked[dict[str, set[self.capset.captype]] @ DefaultFactory(dict)],
            self.capability_file,
        )

    def has_capability(self, email, cap):
        cd = self.capability_db.value
        return cap in Capability(implies=cd.get(email, set()))

    def ensure_user_manager(self, email):
        if self.user_management_capability is None or not self.has_capability(
            email, self.user_management_capability
        ):
            raise HTTPException(
                status_code=403, detail=f"{self.user_management_capability} capability is required"
            )

    async def get_user(self, request: Request):
        if auth := request.headers.get("Authorization"):
            match auth.split("Bearer "):
                case ("", rtoken):
                    rtoken = self.secrets_serializer.loads(rtoken)
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
            cap = deserialize(self.capset.captype, cap)

        async def get(request: Request):
            if redirect:
                email = await self.ensure_email(request)
            else:
                email = await self.get_email(request)
            if email is None:
                raise HTTPException(status_code=401, detail="Authentication required")
            elif cap is None or self.has_capability(email, cap):
                yield email
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

    async def route_login(self, request):
        red = request.session.get("redirect_after_login", "/")
        request.session.clear()
        request.session["redirect_after_login"] = red
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
        await self.assimilate_payload(request)
        red = request.session.get("redirect_after_login", "/")
        return RedirectResponse(url=red)

    async def route_token(self, request):
        if state := request.query_params.get("state"):
            await self.assimilate_payload(request)

        if not (rt := request.session.get("refresh_token")):
            if not state:
                login_url = request.url_for("login")
                return RedirectResponse(url=f"{login_url}?offline_token=true&redirect=token")
            else:  # pragma: no cover
                return PlainTextResponse("Unauthorized", status_code=401)

        ert = self.secrets_serializer.dumps(rt)
        return JSONResponse({"refresh_token": ert})

    async def route_logout(self, request):
        request.session.clear()
        return RedirectResponse(url="/")

    def _manage_cap_response(self, email):
        db = self.capability_db
        return JSONResponse(
            {
                "status": "ok",
                "email": email,
                "capabilities": serialize(set[self.capset.captype], db.value.get(email, set())),
            }
        )

    async def _manage_generic(self, request, reqcls):
        user = await self.get_email(request)
        self.ensure_user_manager(user)

        req = deserialize(reqcls, await request.json())

        db = self.capability_db
        req.apply(db.value)
        db.save()

        return self._manage_cap_response(req.email)

    async def route_manage_capabilities_add(self, request):
        @dataclass
        class AddRequest:
            email: str
            capability: self.capset.captype

            def apply(self, caps):
                caps.setdefault(self.email, set()).add(self.capability)

        return await self._manage_generic(request, AddRequest)

    async def route_manage_capabilities_remove(self, request):
        @dataclass
        class RemoveRequest:
            email: str
            capability: self.capset.captype

            def apply(self, caps):
                caps.setdefault(self.email, set()).discard(self.capability)

        return await self._manage_generic(request, RemoveRequest)

    async def route_manage_capabilities_set(self, request):
        @dataclass
        class SetRequest:
            email: str
            capabilities: set[self.capset.captype]

            def apply(self, caps):
                caps[self.email] = self.capabilities

        return await self._manage_generic(request, SetRequest)

    async def route_manage_capabilities_list(self, request):
        user = await self.get_email(request)

        @dataclass
        class ListRequest:
            email: str = user

        req = deserialize(ListRequest, dict(request.query_params))

        if req.email != user:
            self.ensure_user_manager(user)

        return self._manage_cap_response(req.email)

    def install(self, app):
        if not self.enable:  # pragma: no cover
            return

        app.add_middleware(
            SessionMiddleware,
            secret_key=self.secret_key,
            max_age=14 * 24 * 60 * 60,
        )

        oauth = OAuth()
        oauth.register(
            name="ezo",
            client_id=self.client_id,
            client_secret=self.client_secret,
            server_metadata_url=self.server_metadata_url,
            client_kwargs=self.client_kwargs,
        )
        self.oauth = getattr(oauth, "ezo")

        app.add_route("/login", self.route_login, name="login")
        app.add_route("/logout", self.route_logout)
        app.add_route("/auth", self.route_auth, name="auth")
        app.add_route("/token", self.route_token, name="token")

        if self.user_management_capability:
            app.add_route(
                "/manage_capabilities/add", self.route_manage_capabilities_add, methods=["POST"]
            )
            app.add_route(
                "/manage_capabilities/remove",
                self.route_manage_capabilities_remove,
                methods=["POST"],
            )
            app.add_route(
                "/manage_capabilities/set",
                self.route_manage_capabilities_set,
                methods=["POST"],
            )

        app.add_route("/manage_capabilities/list", self.route_manage_capabilities_list)

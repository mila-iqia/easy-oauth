import shutil
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from serieux import deserialize
from starlette.requests import Request

from easy_oauth.cap import Capability
from easy_oauth.manager import OAuthManager

here = Path(__file__).parent


def make_app(tmpdir: Path = None):
    app = FastAPI()
    oauth = deserialize(OAuthManager, Path(here / "appconfig.yaml"))
    if tmpdir is not None:
        dest_cap_file = Path(tmpdir) / oauth.capability_file.name
        shutil.copy(oauth.capability_file, dest_cap_file)
        oauth.capability_file = dest_cap_file

    user_management = Capability("user_management")

    oauth.install(app, user_management_capability=user_management)

    reg = oauth.register_capability

    reg(villager := Capability("villager"))
    reg(mafia := Capability("mafia", [villager]))
    reg(police := Capability("police", [villager]))
    reg(mayor := Capability("mayor", [villager, police]))
    reg(baker := Capability("baker", [villager]))
    reg(admin := Capability("admin", [villager, mafia, baker, mayor, user_management]))

    @app.get("/")
    async def route_root():
        return PlainTextResponse("root")

    @app.get("/health")
    async def route_health():
        return JSONResponse({"active": True})

    @app.get("/hello")
    async def route_hello(request: Request, email: str = Depends(oauth.get_email)):
        return PlainTextResponse(f"Hello, {email}!")

    @app.get("/hello_ensure")
    async def route_hello_ensure(request: Request, email: str = Depends(oauth.ensure_email)):
        return PlainTextResponse(f"Hello, {email}!")

    @app.get("/murder")
    async def route_murder(
        request: Request,
        target: str,
        email: str = Depends(oauth.get_email_capability(mafia)),
    ):
        return PlainTextResponse(f"{target} was murdered by {email}")

    @app.get("/bake")
    async def route_bake(
        request: Request,
        food: str,
        email: str = Depends(oauth.get_email_capability(baker, redirect=True)),
    ):
        return PlainTextResponse(f"{food} was baked by {email}")

    @app.get("/god")
    async def route_god(
        request: Request,
        email: str = Depends(oauth.get_email_capability(admin)),
    ):
        return PlainTextResponse(f"{email} is god")

    return app

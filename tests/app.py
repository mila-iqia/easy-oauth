import os
from pathlib import Path
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from serieux import deserialize
from serieux.features.encrypt import EncryptionKey
from starlette.requests import Request

from easy_oauth.manager import OAuthManager


here = Path(__file__).parent


def make_app():
    app = FastAPI()
    oauth = deserialize(OAuthManager, Path(here / "appconfig.yaml"))
    oauth.install(app)

    @app.get("/health")
    async def route_health():
        return JSONResponse({"active": True})

    # @app.get("/hello")
    # async def route_hello(request: Request, email: str = Depends(oauth.get_email)):
    #     return PlainTextResponse(f"Hello!")

    @app.get("/hello")
    async def route_hello(request: Request, email: str = Depends(oauth.get_email)):
        return PlainTextResponse(f"Hello, {email}!")

    return app

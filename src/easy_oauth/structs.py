import base64
import json
from dataclasses import dataclass, field

import httpx
from serieux import deserialize

from .cap import Capability


class Base:
    class SerieuxConfig:
        allow_extras = True


@dataclass(kw_only=True)
class OpenIDConfiguration(Base):
    issuer: str
    authorization_endpoint: str
    device_authorization_endpoint: str = None
    token_endpoint: str
    userinfo_endpoint: str = None
    revocation_endpoint: str = None
    jwks_uri: str = None
    response_types_supported: list[str] = field(default_factory=list)
    response_modes_supported: list[str] = field(default_factory=list)
    subject_types_supported: list[str] = field(default_factory=list)
    id_token_signing_alg_values_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    claims_supported: list[str] = field(default_factory=list)

    @classmethod
    def serieux_from_string(cls, url):
        resp = httpx.get(url)
        resp.raise_for_status()
        data = resp.json()
        return deserialize(cls, data)


@dataclass
class UserInfo(Base):
    # User's email address
    email: str

    # The user's unique ID
    sub: str

    # User capability
    caps: set[Capability] = field(default_factory=set)

    @classmethod
    def serieux_from_string(cls, idtoken):
        parts = idtoken.split(".")
        assert len(parts) == 3
        padding = "=" * (-len(parts[1]) % 4)
        payload_b64 = parts[1] + padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        idtoken_payload = json.loads(payload_bytes.decode("utf-8"))
        assert isinstance(idtoken_payload, dict)
        return deserialize(cls, idtoken_payload)


@dataclass
class Payload(Base):
    access_token: str = None
    refresh_token: str = None
    token_type: str = None
    userinfo: UserInfo = None

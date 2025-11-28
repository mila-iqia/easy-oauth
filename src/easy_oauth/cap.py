from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from serieux import deserialize
from serieux.features.filebacked import DefaultFactory, FileBacked
from serieux.features.registered import Registry


@dataclass(eq=False)
class Capability:
    name: str = None
    implies: set["Capability"] = field(default_factory=set)

    def __contains__(self, cap):
        return cap is self or any(cap in cap2 for cap2 in self.implies)

    def __str__(self):
        return self.name or "&".join(map(str, self.implies)) or "none"

    __repr__ = __str__


@dataclass
class CapabilitySet:
    graph: dict[str, list[str]]
    auto_admin: bool = True
    user_file: Path = None
    user_overrides: dict[str, list[str]] = field(default_factory=dict)
    default_capabilities: list[str] = field(default_factory=list)
    guest_capabilities: list[str] = field(default_factory=list)

    # [serieux: ignore]
    registry: Registry = None

    # [serieux: ignore]
    captype: type = None

    def __post_init__(self):
        self.registry = Registry()
        for name in self.graph:
            self.registry.register(name, Capability(name))
        for name, implies in self.graph.items():
            self[name].implies.update(self[n] for n in implies)
        if self.auto_admin:
            self.registry.register(
                "admin", Capability("admin", set(self.registry.registry.values()))
            )
        self.captype = Capability @ self.registry
        self._user_overrides = deserialize(dict[str, set[self.captype]], self.user_overrides)
        self._default_capabilities = deserialize(set[self.captype], self.default_capabilities)
        self._guest_capabilities = deserialize(set[self.captype], self.guest_capabilities)

    def __getitem__(self, item):
        return self.registry.registry[item]

    @cached_property
    def db(self):
        return deserialize(
            FileBacked[dict[str, set[self.captype]] @ DefaultFactory(dict)],
            self.user_file,
        )

    def check(self, email, cap):
        if email is None:
            # Guest user (not authenticated)
            return cap in Capability(implies=self._guest_capabilities)

        caps = self.db.value.get(email, set())
        overrides = self._user_overrides.get(email, set())
        return cap in Capability(implies={*caps, *overrides, *self._default_capabilities})

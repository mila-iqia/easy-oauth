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


class CapabilitySet:
    def __init__(
        self,
        graph: dict[str, list[str]],
        auto_admin: bool = True,
        user_file: Path = None,
    ):
        self.registry = Registry()
        for name in graph:
            self.registry.register(name, Capability(name))
        for name, implies in graph.items():
            self[name].implies.update(self[n] for n in implies)
        if auto_admin:
            self.registry.register(
                "admin", Capability("admin", set(self.registry.registry.values()))
            )
        self.captype = Capability @ self.registry
        self.user_file = user_file

    def __getitem__(self, item):
        return self.registry.registry[item]

    @cached_property
    def db(self):
        return deserialize(
            FileBacked[dict[str, set[self.captype]] @ DefaultFactory(dict)],
            self.user_file,
        )

    def check(self, email, cap):
        return cap in Capability(implies=self.db.value.get(email, set()))

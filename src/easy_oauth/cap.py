from __future__ import annotations

from dataclasses import dataclass, field

from serieux.features.registered import Registry


@dataclass(eq=False)
class Capability:
    name: str = None
    implies: set[Capability] = field(default_factory=set)

    def __contains__(self, cap):
        return cap is self or any(cap in cap2 for cap2 in self.implies)

    def __str__(self):
        return self.name or "&".join(map(str, self.implies)) or "none"

    __repr__ = __str__


class CapabilitySet:
    def __init__(self, capabilities: dict[str, list[str]], auto_admin: bool = True):
        self.registry = Registry()
        for name in capabilities:
            self.registry.register(name, Capability(name))
        for name, implies in capabilities.items():
            self[name].implies.update(self[n] for n in implies)
        if auto_admin:
            self.registry.register(
                "admin", Capability("admin", set(self.registry.registry.values()))
            )
        self.captype = Capability @ self.registry

    def __getitem__(self, item):
        return self.registry.registry[item]

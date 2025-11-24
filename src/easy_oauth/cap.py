from __future__ import annotations

from dataclasses import dataclass, field

registered_capabilities = {}


@dataclass(frozen=True, eq=False)
class Capability:
    name: str = None
    implies: frozenset[Capability] = field(default_factory=frozenset)
    registered: bool = False

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.__registry__ = {}

    @classmethod
    def register(cls, name, implies=None):
        cap = cls(name, set() if implies is None else implies, True)
        registry = cls.__registry__
        registry[name] = cap
        return cap

    def iter(self):
        if self.registered:
            yield self
        for cap in self.implies:
            yield from cap.iter()

    def __contains__(self, cap):
        return cap is self or any(cap in cap2 for cap2 in self.implies)

    def __str__(self):
        return self.name or "&".join(map(str, self.implies)) or "none"

    __repr__ = __str__

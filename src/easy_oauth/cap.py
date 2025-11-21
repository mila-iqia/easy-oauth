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
        return cap is self or any(cap2.has(cap) for cap2 in self.implies)

    def __str__(self):
        return self.name or "&".join(map(str, self.implies)) or "none"

    __repr__ = __str__

    @classmethod
    def serieux_from_string(cls, s):
        registry = cls.__registry__
        return registry[s]

    @classmethod
    def serieux_from_list(cls, caps):
        registry = cls.__registry__
        return cls(implies={registry[s] for s in caps})
